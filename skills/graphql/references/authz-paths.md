# Authorization — test paths, not types

REST gives one route per resource. GraphQL gives a **graph**, and a type is usually
reachable several ways. Developers protect the obvious route and miss the others.
This is the highest-yield idea in the whole skill, and it is mechanical.

## Contents

- Enumerate every path to the type
- Where the authorization actually lives
- Directives: introspectable, but their placement is not
- Operation-name allow lists spoof themselves
- The token is often an argument, not a header
- IP allow lists and the headers that fake them
- Free wins in the schema

## Enumerate every path to the type

A `PasteObject` may be reachable through `pastes`, `paste(id:)`, `readAndBurn(id:)`
*and* `search(keyword:)`. A `User` may be reachable through `user(id:)`, `me`,
`node(id:)`, an `owner` field on some other object, and a union member in a search
result. Each is a separate authorization decision written by a human.

```bash
# with the introspection JSON on disk
graphql-path-enum -i introspection.json -t UserObject
# -> Query (users) -> UserObject
#    Query (me) -> UserObject
#    Query (search) -> SearchResult -> UserObject
#    PasteObject (owner) -> OwnerObject -> UserObject
```

Without the tool, do it by hand from the schema: find every field anywhere in the
graph whose type is the target type, and walk back to a root operation. Nested
paths — reaching `User` *through* another object's field — are the ones that get
missed, because the developer guarding `users(id:)` never thought about
`paste.owner`.

Then test each path with the **same** restricted identity and compare. Send them as
aliases in one request (`batching-abuse.md`) so session state, timing and
throttling cannot explain a difference:

```graphql
query {
  direct:  user(id: "<victim>") { id email }
  viaNode: node(id: "<victim-global-id>") { ... on User { id email } }
  viaSearch: search(keyword: "<victim-email>") { ... on User { id email } }
}
```

**One path returning data while the others return `null` with an authorization
error is the finding**, and the refusing siblings are the strongest sentence in the
report — the correct check exists in this codebase and was not applied here. That
is control 7 in `../../broken-access-control/references/controls.md`; the whole
control matrix applies, run it.

Relay-style `node(id:)` deserves its own attention: it exists to fetch *any* object
by a global id, so it is a single field that reaches most of the graph. The ids are
usually base64 of `TypeName:id` — decode one, re-encode another, and see whether
the resolver re-checks ownership.

## Where the authorization actually lives

Two architectures, and the tell is cheap:

- **out-of-band** — a gateway, sidecar or WAF authenticates before the resolver
  ever runs. Tell: a well-formed query returns **`401`/`403` with no GraphQL
  `errors` body**. Attacks here are ordinary gateway attacks; the GraphQL layer
  never saw you.
- **in-band** — the API implements login and permissions itself. Tell: **`200` with
  an `errors` entry**. This is the vulnerable one, because permission logic is
  duplicated per entry point — which is exactly what path enumeration exploits.

The error text usually names the library, which tells you its defaults:

| Error message | Implementation |
|---|---|
| `Authentication credentials are missing`, `Authorization header is required and must contain a value` | OAuth2 bearer + JWT |
| `Not Authorised!` | GraphQL Shield |
| `Not logged in`, `Auth required`, `API key is required` | GraphQL Modules |
| `Invalid token!`, `Invalid role!` | graphql-directive-auth |

**GraphQL Shield's `fallbackRule` defaults to allow** — any field the developer
forgot to write a rule for is permitted. That makes "find the field nobody wrote a
rule for" a concrete objective rather than a hope, and newly added fields are the
likeliest candidates.

## Directives: introspectable, but their placement is not

Ask the schema which authorization directives exist:

```graphql
{ __schema { directives { name args { name } locations } } }
```

`@auth(requires:)`, `@hasRole(role:)`, `@protect(role:)`, `@authz`, `@authorize`,
`@permissions` — any of these means field-level authorization is the model.

**Introspection does not expose where schema directives are applied.** You can
learn that `@auth` exists; you cannot learn that it decorates `User.password` and
not `User.email`. There is no shortcut: request the sensitive fields and read what
comes back. This is why field-level authorization in GraphQL is under-tested, and
why it is worth testing.

Two structural places the decoration goes missing:

- **interfaces.** Every type implementing an interface must declare the interface's
  fields, and each declaration needs its own directive. In a schema of thousands of
  lines, one implementor missing `@auth` on a shared field is invisible to review
  and obvious to a request.
- **unions and search results.** A type that is guarded on its own query is often
  unguarded when returned as a union member, because the union's resolver is
  written once and inherits nothing.

Field-level authorization is also frequently applied **after** the resolver has
already run its business logic — so a mutation may perform its side effect and
*then* refuse to show you the result. If a mutation returns an authorization error,
check whether the state changed anyway.

## Operation-name allow lists spoof themselves

Some deployments allow unauthenticated traffic only for a named set of operations —
`RegisterAccount`, `Login` — by matching the **operation name**. The operation name
is a free-form label the client chooses and it has no relationship to what the
document does:

```graphql
mutation RegisterAccount {          # the allow-listed name
  withdrawal(amount: 100.00, from: "ACT001", dest: "ACT002") { confirmationCode }
}
```

If unauthenticated access is gated on a name, it is gated on nothing. Test it the
moment you see evidence of a name-keyed policy: rename a rejected operation to a
name you know is permitted and resend, unchanged otherwise. That single-variable
swap is the whole proof.

The same property matters for logs: an audit trail that records operation names
records whatever you typed, so what a defender sees can be chosen by the attacker.
Say so in the report — it is an impact multiplier, and the operation name is also
an injection sink (`injection-forgery.md`).

## The token is often an argument, not a header

GraphQL deployments frequently carry the credential **inside the document**:

```graphql
query { me(token: "eyJ...") { id username email } }
```

Consequences worth acting on. The token appears in the request body rather than a
header, so header-oriented tooling and header-scoped WAF rules never inspect it.
It is aliasable and therefore batchable — many tokens per request. And it lands in
logs, referrers and caches whenever GET queries are supported.

Everything else about the token is owned by `../../auth-flow-bypass`: `alg:none`,
RS256→HS256 confusion, an unverified signature, and claims carrying secrets
(payloads with an embedded `api_token` are real). Decode every token you see before
attacking it — the payload is base64, and reading it is free.

## IP allow lists and the headers that fake them

Internal GraphQL APIs often skip per-client authentication and allow-list source
addresses instead, taking the address from a header a proxy is trusted to set:

```bash
for h in X-Forwarded-For X-Real-IP X-Originating-IP X-Client-IP X-Host True-Client-IP; do
  curl -s -X POST "$U" -H 'Content-Type: application/json' \
       -H "$h: 127.0.0.1" -d '{"query":"{__typename}"}' -o /dev/null -w "$h %{http_code}\n"
done
```

A differential against the same request without the header is the finding. Pair it
with the internal-range values the app is likely to trust (`10.0.0.1`, `127.0.0.1`,
`192.168.0.1`). The WAF-origin variant of this is owned by
`../../broken-access-control/references/edge-filter-bypass.md`.

## Free wins in the schema

- **Sort enums.** `users(order: {sort: ID})` returns the earliest-created account
  first — which is nearly always the built-in super-admin. A sort argument is an
  identity oracle for the highest-value account on the platform.
- **`limit: -1`** interpreted as "no limit" (`batching-abuse.md`).
- **Fields the UI never renders.** `internalNotes`, `adminComment`, `riskScore`,
  `passwordHash`, `apiKey`, `isAdmin` — request them on objects you *are* entitled
  to first. Excessive data exposure on your own object is a weaker finding, but it
  tells you the resolver returns whole rows, which is what makes the cross-user
  version worth chasing.

## Source

Distilled from *Black Hat GraphQL* (Aleks & Farhi, No Starch Press, 2023),
chapter 7, with the schema mechanics from chapter 3. `graphql-path-enum` is that
book's toolchain; the manual method above needs only the introspection response.
