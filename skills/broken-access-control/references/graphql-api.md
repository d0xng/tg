# API Surface — body-field spoof, tenant-header routing, version downgrade, GraphQL

## Contents

- Method
- 1. Body-field identity spoof
- 2. Org/tenant header as routing key
- 3. API-version downgrade
- 4. GraphQL introspection + alias-batch
- 5. Read-only vs write token scope
- High-value patterns
- Good evidence
- Handoffs

Use when authorization differs across REST/GraphQL/mobile/internal APIs, versions,
or token scopes, or when identity is carried in a body field or tenant header. Safe
ladder: the **Rung mapping** above.

## Method

1. Collect op names / routes from JS, source maps, mobile traffic, and Burp history;
   note every body identity field (any `user_id`/`ownerId`/`accountId`-style field),
   tenant/org header, API version, and `x-api-key`.
2. Map each to required role/object/permission; **negative control** each.
3. Replay hidden ops / spoofed bodies / foreign tenant headers / older versions with
   the restricted actor on synthetic data.
4. Compare siblings (list/detail, create/update/delete, v2/v1) — find the enforcer.

## 1. Body-field identity spoof

The gateway validates the Bearer signature, but the handler trusts an identity field in
the JSON body (a `user_id`/`userId`/`ownerId`/`author`-style field) instead of binding
the action to the token `sub`. Common on feedback/rating, comments, profile, "report
abuse", and on-behalf-of writes; usually write-only. Often paired with an `x-api-key`
that is a public web-client id (an input, not a leak).

- **Attack**: replay your own authenticated write with the identity field swapped to a
  second account you control.
- **Oracle ladder** (run in order): no-Bearer → 401/403 (sig enforced); own Bearer +
  own id → 200 (baseline); own Bearer + the other account's id → 200/201 (spoof — bound
  to the body, not the token); well-formed but nonexistent id → no "not found" (no
  registry check); empty id → 400 "missing required field" (reads the body id, never
  cross-checks the sub); extra unschemaed fields (a `role`/`prompt`/`rating` the client
  never sends) accepted → metric/RLHF poisoning; GET on the route → 405 (write-only).

A second product/API variant of the same bug typically differs only in host, key, and
the identity-field name — check sibling services for the same shape. Converts Medium if
write-only; hunt the read side / downstream Trust-&-Safety routing to raise it.

## 2. Org/tenant header as routing key

The server takes the acting tenant from a request header (an `X-Org-Id`/`tenant`/
`accountId`-style header) and uses it as a lookup/routing key without verifying
membership. List endpoints are scoped (empty for non-members); per-object endpoints are
not.

- **Read**: set the header to a victim org id (leaked via avatar/CDN paths, other users'
  JWTs, a public teams/members route) and request a per-object route (status, detail,
  executions, download) → its presigned content. A structured storage key returned in
  the body — shaped like `{orgId}/{userId}/{resource}` — both confirms cross-tenant
  reach and lets you predict sibling object ids; low-entropy object ids (a date + short
  hex) make enumeration trivial.
- **Cost amplification**: send a *consumer*-tier bearer (identifiable by its plan/
  entitlement claims) with any org value — even an all-zero uuid — to a compute-bearing
  action (LLM/inference/render) → work billed to the provider's org.
- **Oracle**: victim org + object → read; a *wrong* (non-existent) org → **404 (the
  header routes, it does not authorize)**; garbage org value → no validation; a sibling
  action that DOES gate entitlement → 403 (an entitlement / "not entitled" error) — the
  convincer that proves the missing check.

Cost amplification (billed compute, documented entitlement gate) scores higher than the
read — also hand to `resource-abuse`.

## 3. API-version downgrade

Authorization middleware is often added only to the newest version. Replay the
identical authenticated request against the old handler.

```bash
# v2 enforces; v1 (same body) does not
curl -s "https://$HOST/api/v2/orders/1002" -H "$AUTH"   # -> 403
curl -s "https://$HOST/api/v1/orders/1002" -H "$AUTH"   # -> 200 + restricted data
```

Also try: strip the version (`/api/orders/1002`), `/api/legacy/`, and swapping the
version inside nested paths (`/v2/users/me/v1/orders/1002`). Oracle: v1 identical
body → 200 where v2 → 403.

## 4. GraphQL — the access-control slice

The authorization question in GraphQL is **per path, not per type**: the same object
is usually reachable through several queries (`user(id:)`, `me`, `node(id:)`,
`search`, another object's `owner` field), each one a separately written check.
Enumerate them all, request the object through each with the same restricted
identity, and compare — one path answering while its siblings refuse is control 7
in `controls.md` and the strongest line in the report.

```bash
# the entry points and their arguments, in one request
curl -s "https://$HOST/graphql" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{fields{name}} mutationType{fields{name}} directives{name}}}"}'
```

Look for fields the UI never shows (`internalNotes`, `creditCard`, `adminToken`,
`role`, `email`), mutations absent from the UI, and an `@auth`/`@hasRole` directive
— whose *placement* introspection will not tell you, so it must be tested field by
field.

**Everything else GraphQL-specific is owned by `../../graphql`** and is not
duplicated here: recovering the schema when introspection is disabled, alias
batching and what it defeats, path enumeration, the four injection surfaces, and
subscription hijacking. Open that skill the moment the target speaks GraphQL; come
back here for the control matrix and the verdict.

## 5. Read-only vs write token scope

Generate a token with an explicit limited scope, then attempt an adjacent
write/delete/read the scope should forbid. Oracle: the endpoint checks
authentication but not scope → the narrow token performs the wide action.

## High-value patterns

hidden mutation lacks a role check; read-only token writes; token with one
permission performs an adjacent action; GraphQL node/interface exposes an object
outside the visible UI; disabled account still uses the API/GraphQL; internal API
accepts a browser session without role; mobile route skips web middleware; bulk/alias
mutation performs what the individual route denies.

## Good evidence

exact op/route + restricted actor; success + persisted state; the enforcing sibling
denying the same actor; token scope / role label proving the expected restriction;
negative control (no-auth/foreign-tenant) denying.

## Handoffs

- pure id-swap with function check intact → `idor-bola` (keep the function half here);
- cross-tenant via org header → `tenant-isolation`; billed cost → `resource-abuse`;
- PII at scale → `validation` after ONE bounded proof (do not bulk-dump).
