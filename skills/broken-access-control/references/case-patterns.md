# Case Patterns — generalized technique catalog

## Contents

- Any valid token (incl. guest/anon) → admin route namespace (+ WAF-origin)
- Cognito self-writable custom attribute → tenant takeover
- Dual-authorizer admin API Gateway
- Mobile cred chain: Firebase RemoteConfig + alg:none + hardcoded HMAC
- Body-field identity spoof
- Org/tenant header as routing key
- Sequential-id BOLA on an order/management API
- Public-report BAC patterns (for classes not yet catalogued above)
- Evidence-upgrade heuristic

Distilled BAC hunting shapes, each with the generalized replay (placeholders) and a
neutral "converts to <sev> when <condition>" verdict so you rate honestly and don't
over-inflate. These are recognition patterns, not detectors: seeing the shape means
"probe this class," not "it's vulnerable."

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Any valid token (incl. guest/anon) → admin route namespace (+ WAF-origin)

An unauth guest/anon login (or a hardcoded JS key that mints a token) returns a *usable*
bearer, and an admin route namespace enforces authentication but never re-checks role →
any valid token reads it. Recognize an admin/back-office route family (an `/api/admin/*`
-style prefix, a `*-mgmt`/console group) the normal UI never calls, commonly 20+ sibling
routes; plus any unauth path minting a bearer. Oracle: guest token → 200 + data on an
admin-namespace route where no role was proven; an enforcing sibling → 403. WAF-fronted →
recover the origin and dial it (`role-matrix.md` §1 owns the ladder).
The guest-login / hardcoded key is a public client input, not a leak. Full method:
`role-matrix.md` §1. **Converts: Critical** when the admin group returns cross-user PII;
**High** when it returns non-PII privileged data. The reachable route alone is not a
finding. Replay: find the guest/anon token + admin namespace in JS → replay with the
guest token, read ONE row → WAF? origin bypass per `role-matrix.md` §1 → note enumerable
ids for per-record IDOR.

## Cognito self-writable custom attribute → tenant takeover

Access token `scope: aws.cognito.signin.user.admin` + a backend that authorizes tenancy
from a self-writable custom attribute (`custom:<tenantAttr>`). The universal AWS API
`UpdateUserAttributes` overwrites the tenancy attr → re-auth (`InitiateAuth`) mints a JWT
with the forged claim → the app's tenant-scoped read returns the other tenant's PII. On
any Cognito multi-tenant app, always test `GetUser`/`UpdateUserAttributes` writability of
authz-bearing custom attrs. Full method: the `cloud-exploitation` skill
§5c (AWS API mechanics) + the `tenant-isolation` skill (tenant
chain); recognition and verdict here and in `invitation-identity.md` §A2. **Converts:
Critical (P1)**. The `UpdateUserAttributes` 200 alone is N/A. Revert the attribute after
the single read.

## Dual-authorizer admin API Gateway

A second internal `*.execute-api.<region>.amazonaws.com` where most routes need IAM
SigV4 (a plain JWT returns `"Credential should be scoped to a valid region"`) but a few
accept a plain Cognito `id_token`, and the Lambda does zero ownership check. Recognize a
200-returning internal route that names a source object owned by another account AND a
caller-controlled destination (copy/clone/export/share with a destination email/account
field): resolve the victim's account id via an enumeration route, invoke the copy route
with the victim's object as source + your identity as destination → the object (S3
content/secrets) clones into your account → read via the main API's presigned URLs.
**Converts: High** when a JWT-accepting route lacks the ownership check AND a
caller-controlled destination exposes another account's object; **Medium** if only the
authorizer gap is proven. Self-signup returning `UserConfirmed:true` lowers the bar.
Method: `role-matrix.md` §2 (function+object hybrid — own it here).

## Mobile cred chain: Firebase RemoteConfig + `alg:none` + hardcoded HMAC

Decompile → Firebase key → Remote Config → base64 Azure `client_id`/`secret` + HMAC
key. Mint an Azure `client_credentials` token, forge an `idtoken` `{"alg":"none"}` +
empty sig (accepted), compute the secondary `x-v-token` HMAC-SHA512 with the leaked
key → the only access control left is the object id (BOLA: e.g. PNR+lastName, cartId).
**Converts: High/Critical** when the forged token performs another user's action;
Firebase-RemoteConfig secret-mining + `alg:none` are high-yield first moves on any
mobile target. Method: `invitation-identity.md` §A1 (+ hand cloud secret mining to
`cloud-exploitation` / `exposed-secrets`).

## Body-field identity spoof

An authenticated write (feedback/rating, comment, profile, "report abuse", on-behalf-of)
carries the acting identity in a body field (a `user_id`/`ownerId`-style field) and the
handler trusts it instead of the Bearer `sub`. No-Bearer → 401 (sig enforced); own
Bearer + own id → 200; swap id to a second account you own → IDOR write; well-formed but
nonexistent id → no registry check; empty id → 400. Usually write-only (GET → 405) so it
**converts Medium** (metric/attribution/RLHF poisoning) — don't over-rate unless you find
the read side / downstream Trust-&-Safety routing. Often paired with an `x-api-key` that
is a public web-client id (an input, not a leak). `-> graphql-api.md`.

## Org/tenant header as routing key

Server takes the acting tenant from a request header (an `X-Org-Id`/`tenant`-style
header) and uses it as a lookup/routing key, never verifying membership: victim org-id +
object id → full read; a wrong (non-existent) org → 404 (the header routes, it does not
authorize); garbage org value (even an all-zero uuid) → no validation. Same gap =
entitlement bypass (a consumer-tier Bearer + any org drives paid inference billed to the
provider). The **enforcing sibling** (a sibling action → 403 with an entitlement / "not
entitled" error) is the convincer.
Converts: **High** when the foreign-tenant response carries tenant-scoped business data or
PII; **Medium** when it is non-sensitive metadata only; **Critical** when it reaches mass
PII (an org user list, or 5–10 distinct bounded records).
Cost-amplification twin — Converts: **High** — a documented entitlement gate plus
quantifiable billed compute; it scores at or above the bare cross-tenant read.
Method owned by the `tenant-isolation` skill §1/§2.

## Sequential-id BOLA on an order/management API

Sequential `orderId` is the only access control. A bare sequential-id read with no
enforcing sibling and no sensitive impact typically **does not convert on its own** —
confirm a sibling enforces to prove the gap, and chain to a write / PII read to
convert. Hand the pure object primitive to `idor-bola`; keep any function-level half here.

---

## Public-report BAC patterns (for classes not yet catalogued above)

- **Invite identity bypass** — invite tied to an email the account can claim without
  verification; accept from an unverified/wrong-session account you own.
  `-> invitation-identity.md` §B.
- **Pending-invite disclosure → escalation** — low member reads a pending owner/admin
  invite email; register/link it; accept the elevated role (owned targets only).
- **Restricted-feature gate bypass** — UI/plan hides a feature; direct API/GraphQL
  route performs it; prove on an owned low-tier workspace. `-> workflow-state.md`.
- **Clone/import bypass** — create is restricted, clone/copy/import is not; clone only
  synthetic/owned objects. `-> workflow-state.md`.
- **Lifecycle persistence** — remove/downgrade a controlled account; replay the old
  token once (timestamped). `-> lifecycle-persistence.md`.
- **Token-scope mismatch** — narrow token performs an adjacent write/read; endpoint
  checks auth not scope. `-> graphql-api.md` §5.
- **Account-recovery trust gap** — reset link/action deliverable to or triggerable
  from an unverified identity; two owned inboxes only; final ATO step → ask d0x directly before executing, not attempted.
- **Attachment/file ownership switch** — flip owner/reference on a controlled
  non-sensitive file, then read via the new relation. `-> public-exposure.md`.
- **Public/private metadata mismatch** — resource private but a JSON/API route leaks
  title/policy/comments/likes; compare allowed vs restricted vs anon.
- **Pre-signed URL scope failure** — URL not bound to user/object/path/method/expiry;
  replay from another owned session / mutate the id. `-> public-exposure.md`.
- **SaaS portal over-exposure** — broad Salesforce/community object perms leak
  records; capture one, infer scale, hand to `validation`.
- **Exposed admin/KVM panel** — passive GET/screenshot only; confirm the host belongs to
  the program's scope before touching it. `-> public-exposure.md`.
- **Privacy-toggle bypass via API** — set hidden on account A, read via
  GraphQL/mobile from B/anon. `-> public-exposure.md`.
- **API-version downgrade** — replay the identical authenticated request against
  `/api/v1/`; older handler lacks the ownership/role middleware. `-> graphql-api.md` §3.
- **GraphQL introspection + alias-batch** — enumerate hidden fields/mutations; alias
  many ids in one request to bypass per-request checks. `-> graphql-api.md` §4.

## Evidence-upgrade heuristic

Raise confidence when two or more hold: server persists the restricted action; a
sibling route denies correctly; UI/docs/permission label says restricted; an old
token/session works after revocation; impact is role escalation / cross-tenant read /
private data / token-session op / account recovery / org control / billed compute.
