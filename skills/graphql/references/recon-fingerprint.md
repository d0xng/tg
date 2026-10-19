# Recon — find it, confirm it, name the implementation

The point of this file is not "there is a GraphQL endpoint." It is to reach the
three facts that change what you do next: **where** it answers, **which**
implementation is behind it, and **what that implementation leaves on by default**.

## Contents

- Where it lives
- Confirm it is GraphQL — `{__typename}` and the two response invariants
- Every endpoint is a separate target
- Fingerprint the implementation from a malformed query
- What the implementation's defaults tell you
- The IDE, and the client-side gate in front of it

## Where it lives

`/graphql` is the default, and it is frequently moved. Sweep these before deciding
the target has no GraphQL:

```
/graphql            /graphql/            /api/graphql        /graphql/api
/v1/graphql         /v2/graphql          /v3/graphql         /graphql/v1
/gql                /query               /api                /index.php?graphql
/graphiql           /playground          /console            /altair
/v1/graphiql        /v2/playground       /subscriptions      /graphql/console
```

Common ports when it is not on 80/443: `4000-4005`, `8000`, `8080`, `8443`, `3000`,
`5013`. The IDE paths matter as much as the API paths — they are a *different*
endpoint on the same host, and the next section is why that matters.

## Confirm it is GraphQL — `{__typename}` and the two response invariants

`__typename` is a meta-field mandated by the specification, so it answers on every
conformant server without any knowledge of the schema:

```bash
# POST (the normal case)
curl -s -X POST "$U" -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
# -> {"data":{"__typename":"Query"}}     (the root type name; usually "Query")

# GET (only where GET queries are supported — its own finding, see injection-forgery.md)
curl -s "$U?query=%7B__typename%7D"

# and the tell you get for free from a bare GET with no query at all:
curl -s "$U"
# -> {"errors":[{"message":"Must provide query string."}]}
```

Two invariants define a GraphQL response, and they are your detection oracle:

1. a valid operation returns a top-level **`data`** key;
2. an invalid one returns a top-level **`errors`** key — *usually with HTTP 200*.

**A `200` carrying `errors` is the normal failure mode, not a success.** Read the
body, never the status. Conversely a `403`/`401` on a well-formed query means
something in front of the API rejected you — a gateway or WAF, not the resolver —
which is itself information (`authz-paths.md` §in-band vs out-of-band).

## Every endpoint is a separate target

This is the cheapest finding in the whole skill and it is routinely skipped. When a
host exposes both an API path and an IDE path, they are usually **two separately
configured views of the same schema**, and the IDE one is configured for
developers:

- introspection disabled on `/graphql`, enabled on `/graphiql`;
- stack traces suppressed on `/graphql`, returned on `/graphiql`;
- authentication enforced on one, absent on the other;
- different WAF rules, because only the documented path was added to the policy.

So run the full battery — introspection probe, malformed query, auth-less
request — **against each path independently**, and record the differential. Two
endpoints that disagree is the observation; the one that answers is the one you
work.

## Fingerprint the implementation from a malformed query

Implementations disagree about everything except the happy path. Send a query that
violates the spec and read the *shape* of the error:

```bash
curl -s -X POST "$U" -H 'Content-Type: application/json' \
  -d '{"query":"queryy {__typename}"}'
```

- a top-level **`syntaxError`** key, `Invalid input "queryy", expected
  ExecutableDefinition` → Sangria (Scala)
- `Validation error of type InvalidSyntax`, plus `validationErrorType`,
  `queryPath`, `errorType`, and an `extensions` object → graphql-java /
  HyperGraphQL
- `Syntax Error GraphQL (1:1)` with `locations` only → graphql-js family (Apollo,
  Yoga, Express-GraphQL)
- Python `Graphene`/`Ariadne` and PHP `graphql-php` each have their own wording

`graphw00f` (`-d` detect, `-f` fingerprint, `-w` custom wordlist) automates this
across 24+ implementations and prints a link to that implementation's page in the
**GraphQL Threat Matrix**. Use the tool if it is installed; the manual probe above
is enough to route when it is not.

Two more discriminators worth knowing because they need no error at all:
**alias character handling** (graphql-php accepts `$` in an alias where most reject
it) and whether **array batching** is accepted (few implementations support it —
see `batching-abuse.md`).

## What the implementation's defaults tell you

Naming the implementation matters because it predicts the controls, and defaults
are rarely changed. The features to resolve, per implementation:

| Feature | Why you care |
|---|---|
| **Introspection** | on by default nearly everywhere; **Graphene, graphql-go and graphql-java ship no supported way to turn it off**, so on those it is almost always reachable |
| **Field suggestions** | on by default in most; this is schema recovery when introspection is off (`schema-recovery.md`) |
| **Query depth limit** | absent → circular-query exposure is real (recognize, never fire) |
| **Query cost analysis** | absent → batching and duplication are unmetered |
| **Automatic persisted queries** | changes the request shape entirely, and an APQ allow list is a real control — recognize it before concluding an operation is reachable |
| **Debug mode** | verbose errors and stack traces (`schema-recovery.md`) |
| **Batch requests** | array batching supported or not; alias batching always is |

## The IDE, and the client-side gate in front of it

A reachable GraphiQL / Playground / Altair panel is not itself a finding, but it is
a strong signal the endpoint is under-hardened, and it renders in JavaScript — so
`curl` and header-only scanners miss it. Screenshot-based scanning (EyeWitness with
a headless engine, or `gowitness`) finds these when nothing else does.

**When the IDE says access is rejected, check whether the gate is client-side
before believing it.** A real corpus of deployments gates the IDE on a cookie or a
query parameter the browser sends to itself:

```
Cookie: env=graphiql:disable        ->  change to  graphiql:enable
?debug=1     ?XDEBUG_SESSION_START=PHPSTORM     (Magento's documented form)
```

Flip it and reload. If the panel renders and queries execute, the control was
decorative — and that pattern generalizes: the same deployments tend to gate
introspection and debug output the same way. Route the *bypass* finding through
`../../broken-access-control/references/controls.md`; the panel alone stays in
`notes/`.

## Source

Technique distilled from *Black Hat GraphQL* (Aleks & Farhi, No Starch Press,
2023), chapters 3–4. Tooling named above — `graphw00f`, the GraphQL Threat Matrix,
EyeWitness — is that book's; check availability against
`../../_shared/references/tooling.md` before planning a proof around it, and fall
back to the manual probes here, which need only `curl`.
