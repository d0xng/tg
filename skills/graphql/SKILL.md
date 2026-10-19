---
name: graphql
description: "Assess GraphQL-specific attack surface including schema recovery, alternate query paths, aliases and batching, operation-name injection, CSRF, subscriptions, split-field SSRF, and resolver authorization. Use when a GraphQL endpoint, GraphiQL or playground UI, `data` or `errors` response, `__typename`, `operationName`, persisted query, Apollo/Relay client, field suggestion, or GraphQL WebSocket appears. Route the resulting primitive to its vulnerability-class skill for impact proof."
---

# GraphQL

**The endpoint is rung 0.** Finding `/graphql` is not a finding; neither is an
enabled introspection query. The finding is the data, the identity, or the action
you reach through it — and every one of those routes to a skill that already owns
the impact. This skill owns what is *specific to GraphQL*: how you see the schema,
how one HTTP request becomes a thousand operations, which paths reach a type, and
the four places GraphQL lets you inject that REST does not have.

**One request is the unit that defenses count, and GraphQL breaks it.** That single
idea drives most of what follows. A WAF, a rate limiter and an audit log all reason
about HTTP requests; a GraphQL document holds an unbounded number of operations.
Everything downstream — brute force, enumeration, object-id sweeps, cost — inherits
that asymmetry.

## Read-on-demand references

| file | what it owns |
|---|---|
| `references/recon-fingerprint.md` | finding the endpoint, confirming it *is* GraphQL, fingerprinting the implementation, and reading its defaults |
| `references/schema-recovery.md` | seeing the schema — introspection, the `__type` bypass, field suggestions, field/type stuffing, errors, debug and stack traces |
| `references/batching-abuse.md` | alias and array batching: the rate-limit/WAF asymmetry, bounded proof, and the DoS families you recognize and never fire |
| `references/authz-paths.md` | path enumeration to a type, authorization directives, operation-name allow lists, tokens carried as arguments, IP allow lists |
| `references/injection-forgery.md` | the four injection surfaces, CSRF via content type and GET, split-URL SSRF, and subscription hijacking |

## Method

1. **Confirm and fingerprint** (`recon-fingerprint.md`). `{__typename}` proves it is
   GraphQL; a malformed query's error shape names the implementation; the
   implementation names its own defaults. Test **every** endpoint you find
   separately — `/graphql` and `/graphiql` on one host routinely differ in
   introspection, stack traces and auth.
2. **Get the schema** (`schema-recovery.md`). Introspection if it answers; otherwise
   `__type`, field suggestions and stuffing. Do not skip this because introspection
   is off — that is the case the schema-recovery file exists for, and it is the
   normal case in production.
3. **Read the schema for targets, not for completeness.** Mutations that change
   state, queries that reach identity, arguments that look like URLs, fields that
   look like shell commands, types that hold PII. Then enumerate *every path* to
   each interesting type (`authz-paths.md`).
4. **Test authorization per path, not per type.** The same object reachable through
   three queries is three separate checks, and developers miss some.
5. **Route the impact out.** The moment you have the primitive, it belongs to the
   skill that owns proving it — see Handoffs.

## Trigger map — what you see → what to open

| You see | Open |
|---|---|
| `/graphql` responds; you have no schema | `references/schema-recovery.md` |
| `"Did you mean"` in any error | `references/schema-recovery.md` — suggestions are schema recovery |
| introspection blocked / `__schema` filtered | `references/schema-recovery.md` §`__type` |
| a `login`/`signup`/`verifyOtp`/`resetPassword` mutation | `references/batching-abuse.md`, then `../auth-flow-bypass` |
| an object id argument (`id:`, `node(id:)`, `userId:`) | `references/batching-abuse.md` for the sweep, `../idor-bola` for the verdict |
| a sensitive type reachable more than one way | `references/authz-paths.md` |
| `@auth` / `@hasRole` / `@protect` in the directive list | `references/authz-paths.md` |
| an argument named `url`/`host`/`port`/`path`/`scheme`/`img_url` | `references/injection-forgery.md` §SSRF, then `../ssrf-safe` |
| a field named `system*`/`exec*`/`run*`/`debug*`/`diagnostics*` | `references/injection-forgery.md` §command, then `../rce-hunting` |
| an argument reaching a `filter`/`where`/`orderBy`/`search` | `references/injection-forgery.md` §SQLi, then `../sqli` |
| the server accepts `application/x-www-form-urlencoded` or GET queries | `references/injection-forgery.md` §CSRF |
| `ws(s)://…/subscriptions`, `subscriptionType` non-null | `references/injection-forgery.md` §CSWSH |
| a schema/response holding PII, keys or tenant ids | `../exposed-secrets`, `../tenant-isolation` |

## Converts? — grade honestly

- **Critical / High** — the schema is the delivery mechanism, not the finding:
  unauthenticated access to a mutation that changes another identity's state; a
  path to a type that leaks PII at scale; SSRF reaching internal services or
  metadata; command injection; SQLi extracting a value.
- **Medium** — a genuine cross-user or cross-tenant read through one unprotected
  path while siblings enforce; an entitlement-gated operation running for an
  unentitled identity (route the metering half to `../resource-abuse`).
- **Low / informative — do not file alone**: introspection enabled; field
  suggestions enabled; a GraphiQL/Playground IDE reachable; the schema dumped;
  batching supported; GET queries supported; stack traces in errors. These are
  *enablers*. They belong in `notes/` and in the report's preconditions paragraph,
  and every one of them is auto-discarded standalone
  (`../validation/references/auto-discard.md`).

**The single most common failure in this class is reporting the enabler.** A
schema dump with no reached object is `INVALID:no-poc`. Introspection being on is
how you found the bug, not the bug.

## Non-destructive posture

- **Never fire a DoS payload.** Circular queries, field duplication, alias and
  directive overloading, array batch floods and object-limit overrides are all
  service-degradation actions — rung 5, not attempted. `batching-abuse.md` covers
  how to *recognize* the exposure and state reachability without executing it.
- **Batching is bounded.** Proving that N operations ride in one HTTP request needs
  a small N (2–5) against **your own** accounts and objects. Do not run a real
  credential brute force on production — that is rung 5, and the finding is the
  broken counting model, which a bounded batch already demonstrates.
- **Mutations write.** Every mutation is a state change: own objects only, sentinel
  values, reverted, logged to `writes.jsonl`. A mutation against a third party's
  object requires d0x's approval before execution, carried in the lead, never executed.
- The full ladder is `../_shared/references/safe-ladder.md`.

## Handoffs

`../idor-bola` object-id swaps · `../broken-access-control` function/role gaps and
the control matrix · `../tenant-isolation` org-scoped reads · `../auth-flow-bypass`
tokens, OTP, JWT forgery · `../ssrf-safe` once a URL argument is confirmed reachable
· `../sqli` once an argument reaches a query · `../rce-hunting` command injection ·
`../xss` any payload stored through a mutation and rendered to staff (the
operation name is one such input) · `../exposed-secrets` keys and PII ·
`../resource-abuse` metered or billed operations.
