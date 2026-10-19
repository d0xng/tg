# High-converting access-control arcs -- abstract patterns (read on demand)

These are the shapes the highest-impact access-control bugs take -- the
transferable anti-pattern, NOT a specific target. Recognize them when the
surface fits; never narrow the hunt to them (the general class in
vectors.md is the backbone). No live endpoint is hardcoded here on
purpose: a real host/param would rot and would read like a target list.

Each is one instance of the spine: **primitive (born at a point) -> what it unlocks -> impact.**

## 1. Creds-in-source -> vendor/data API -> PII by email/id

- **Primitive:** a client-side page (email-preferences / unsubscribe / loyalty / newsletter, or any SPA) hardcodes identity/tenant config inline in HTML or a JS bundle -- an API key, a user_guid/integration id, a tenant prefix -- presented as "client config."
- **Unlocks:** those values ARE the authentication for a third-party vendor's subscriber/data API (marketing/ESP, analytics, CRM). The brand can't revoke them without breaking the page.
- **Impact:** a single unauthenticated request returns full PII for **any user by email or id** (address, GPS, internal ids, purchase history, age/minor status). Multi-tenant vendors -> the same key across the brand's whole customer base.
- **How to find it generically:** curl -s the raw HTML of those pages (creds live inline in `<script>`; bundle-mining misses them). Look for vendor CNAMEs / vendor strings in HTTP bodies (any ESP/analytics SaaS). If a brand runs multiple integrations, each integration id may surface different fields -- enumerate them. Prove the object read here; hand the key to exposed-secrets.
- **Portability:** applies to any email-marketing / SaaS-fronted target -- the vendor is interchangeable. The pattern is "public-looking config string = the auth to someone else's data API."

## 2. Tenant/org header as routing key (+ enforcing sibling + cost-amp twin)

- **Primitive:** an org/tenant identifier carried in a header, treated as a routing key rather than an access check.
- **Unlocks:** per-object routes fetch by that header with no membership check; the list route is correctly scoped (so it looks safe).
- **Impact:** cross-tenant read of any object by setting the victim's org header + object id.
- **Convert argument:** find a **sibling route that returns 403 not_entitled** for the same foreign org -- proof the vulnerable route is missing a check its neighbor has. Wrong-org 404 vs valid-foreign 200 is the routing-miss tell.
- **Cost-amplification twin:** the same header is also the billing/entitlement key -- a consumer Bearer + a garbage org id (even 32 zeros) drives paid compute (LLM inference, jobs) billed to the provider with no membership/entitlement check. Same missing check, higher-scoring impact (documented billing gate + amplification).
- Full method: `../../tenant-isolation/references/tenant-vectors.md` §1 (read) and §2 (cost twin) (single owner -- do not restate it here).
- **Dedup:** header-routing reads and their cost-amplification twin recur across targets. Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and -- when the program has one -- its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## 3. Dual-authorizer API

- **Primitive:** a second/internal `*.execute-api` host where most routes enforce IAM/SigV4 but a few were left with a JWT authorizer.
- **Unlocks:** those few routes accept any user's id_token with zero ownership check (differential: JWT-accepts vs IAM-error per route).
- **Impact:** cross-account read; a user-controlled destination field lets you exfil the victim object into your own account.
- Full method: `../../broken-access-control/references/role-matrix.md` §2 (single owner -- do not restate it here).

## 4. Self-writable authz claim (token-carried identity)

- **Primitive:** an access token carries an authz-relevant claim (tenant/org/role) that the user can update on themselves.
- **Unlocks:** overwrite the claim to the victim tenant/role, re-authenticate, and the boundary now resolves to the victim's scope.
- **Impact:** full cross-tenant / privilege escalation. **Revert the claim immediately after proving it.**
- Full method: `../../cloud-exploitation/references/cognito.md` §5c for the AWS `X-Amz-Target` API mechanics, `../../tenant-isolation/references/cognito-takeover.md` for the tenant chain (single owners -- do not restate them here).

## 5. Guest/anonymous -> admin (function-level BAC)

- **Primitive:** a guest/anonymous login token (+ sometimes a hardcoded public key) plus an admin API that exists only in JS.
- **Unlocks:** admin routes with no role check accept the guest session.
- **Impact:** mass PII / config read. Read **one row per admin route**, then the
  bounded 5-10-record scale proof in `../../broken-access-control/references/role-matrix.md`
  §1. **Never paginate the table** -- state the scale by inference from the `count`
  or the pagination header (safe-ladder rung 3).
- Full method: `../../broken-access-control/references/role-matrix.md` §1 (single owner -- do not restate it here).

## 6. Unauth API-Gateway -> datastore CRUD

- **Primitive:** a config key pointing at an API-Gateway stage backed by a datastore Lambda, with no auth.
- **Unlocks:** the Lambda passes input straight to the SDK (empty-body -> SDK validation error, not 401).
- **Impact:** read/write the datastore (read via ReturnValues). Full method: `../../cloud-exploitation/references/dynamodb.md` (single owner -- do not restate it here); run `cloud-exploitation` yourself with the gateway host and stage intact.

## 7. Credential / reset-token read -> account takeover (the Medium->Critical escalation)

- **Primitive:** an object-level read (any IDOR above) whose object carries an auth-bearing field -- a password-reset token, an email-verification / magic-link token, a 2FA/TOTP seed, an OAuth `code`, or a settable email/phone.
- **Unlocks:** you read (or set) the victim's auth material cross-account.
- **Impact:** complete the reset / 2FA on your OWN session and log in as the victim -- full ATO. A read-IDOR on a token is the single highest-value escalation of an otherwise-Medium id-swap; it is what turns a High into a Critical.
- **Discipline:** run the full chain across your two OWN accounts; live-session ATO on a real user = rung 5 (not attempted: ask d0x directly before executing). Concrete step-by-step chain (reset-token, 2FA-seed, settable-email variants): `vectors.md` "IDOR -> ATO".

---

## GraphQL enumeration (aliasing & batching)

When the target exposes GraphQL and a node lookup is not viewer-enforced:

- **Alias fan-out** -- request many objects in ONE query with aliases, each a swapped id:
  ```graphql
  query {
    a: user(id:"User:1001"){ email internalNotes }
    b: user(id:"User:1002"){ email internalNotes }
    c: user(id:"User:1003"){ email internalNotes }
  }
  ```
  Proves enumeration + owner-blind lookup in a single request (fewer calls = gentler on rate limits than a loop). Keep the set **small and bounded** -- enough to show scale, never a flood.
- **Batched operations** -- if the endpoint accepts a JSON array of operations (`[{query...},{query...}]`), send a bounded batch of distinct ids.
- **Introspection** -- pull the schema to reach fields absent from the UI (internalNotes, creditCard, adminToken, resetToken); a hidden sensitive field on a foreign node raises severity.
- **node(id:) / relay ids** -- usually base64("Type:<n>"): decode, swap the int, re-encode. Decode observed ids to learn the id space, then enumerate a small window.
- **Oracle** -- same as REST: compare the returned object's **fields** to prove they're the victim's, not yours or a null/error node. A GraphQL errors block with null data is authz working, not a finding.

Rate discipline applies: batching is preferred **because** it is gentler than a request loop, not a license to pull thousands of nodes.
