# Auth-Flow Case Patterns

## Contents
- Guest/anon token -> admin namespace (+ WAF-origin)
- Cognito self-writable tenant attribute -> tenant takeover
- Dual-authorizer admin API Gateway
- Mobile cred chain: Firebase RemoteConfig + `alg:none` + hardcoded HMAC
- Body-field identity spoof
- Tenant/org identifier trusted as a routing key
- Unauth API-GW -> DynamoDB, `ReturnValues` read side-channel
- Sequential object id as the only access control (BOLA)
- Public-report auth-flow patterns (for classes not yet in the corpus)

A catalog of generalized auth-bypass technique patterns: the shape, how to
recognize the endpoint TYPE, the response-code oracle ladder, and neutral
"converts to <sev> when <condition>" guidance so you rate honestly and don't
over-inflate. These are recognition patterns, not detectors — seeing the shape
means "probe this class," not "it's vulnerable." Dedup before you call it new:
`rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`,
and — when the program has one — its live ledger under
`targets/<program>/reports/`, which wins over any stale export. A match on the
same primitive + same host is CLOSED: rotate to the next angle.

## Guest/anon token -> admin namespace (+ WAF-origin)

A guest/anonymous/pre-auth login issues a *usable* bearer token, and an
admin/management route group authorizes on "is this a valid token?" instead of on
role — so any minted token reads privileged data.
- Recognize it: a login/session endpoint that returns a token with **no user
  credentials** (a "guest", "anonymous", or "try-it" mode), frequently unlocked by
  a hardcoded auth key found in the JS; alongside a route namespace that serves
  cross-user / back-office data (user directories, support/contact messages,
  uploaded files, tender/bid records, internal config).
- Attack: mint the guest/anon token, then replay it against each admin/management
  route.
- Oracle ladder: no token -> 401/403 (auth required); guest token on a normal user
  route -> 200 (the token is genuinely valid); guest token on an admin/management
  route -> 200 with cross-user data = the group has **no role gate** = bypass; a
  CDN/WAF that blocks the admin path at the edge but not at the origin -> recover
  the origin and dial it directly (`../../broken-access-control/references/role-matrix.md` §1 owns the method) -> origin
  serves it = edge-only control.
- Converts: **Critical** when the admin group returns cross-user PII; **High** when it returns non-PII privileged data. The reachable route alone is not a finding. Read ONE row, note sequential ids for per-record IDOR, state scale by inference. Guest-token minting and the replay ladder -> `cognito-auth.md` E; the admin-namespace enumeration and the WAF-origin bypass are owned by `../../broken-access-control/references/role-matrix.md` §1. Object half -> `idor-bola`.

## Cognito self-writable tenant attribute -> tenant takeover

The access token carries `scope: aws.cognito.signin.user.admin` (the user may call
the Cognito user API directly) and the backend derives tenancy from a **custom
attribute** that the pool never marked admin-write-only.
- Recognize it: a Cognito JWT whose `iss` is `cognito-idp.*`, that scope on the
  access token, and a `custom:*` attribute that names an org/tenant/account
  (`custom:tenantId`, `custom:orgId`, `custom:domain`) which the API uses to scope
  data.
- Attack: `UpdateUserAttributes` overwrites the tenant attribute to a **second org
  you control**, re-auth mints a fresh JWT carrying the forged claim, and a
  tenant-scoped read returns the other org's data.
- Oracle ladder: `GetUser` returns the attribute in your writable set (not
  read-only) -> `UpdateUserAttributes` returns 200 (attribute is self-writable, not
  admin-only) -> re-auth -> a tenant-scoped endpoint returns the **other org's**
  records = the attribute drives cross-tenant authorization. Revert the attribute
  immediately after.
- Converts: **Critical (P1)**. The `UpdateUserAttributes` 200 alone is N/A. Recognition + rungs -> `cognito-auth.md` A; the AWS API mechanics are owned by `../../cloud-exploitation/references/cognito.md` §5c and the tenant chain by `../../tenant-isolation/references/cognito-takeover.md`.

## Dual-authorizer admin API Gateway

A *second*, internal `*.execute-api.<region>.amazonaws.com` where most routes
demand IAM SigV4 but a few were mistakenly left on a Cognito JWT authorizer, and
the Lambda behind them does **zero ownership check** on the id in the path/body.
- Recognize it: JS reveals more than one `*.execute-api` host; on the internal one,
  most routes reject a plain Cognito `id_token` with the SigV4 error
  `"Credential should be scoped to a valid region"` while a few accept the JWT.
- Attack: on a JWT-accepting route, supply a **victim object/account id** (no
  ownership check) plus a **user-controlled destination** field, so the action
  moves another account's object into yours; read it back through the main API.
- Oracle ladder: internal route + JWT -> SigV4 region error (IAM-only, skip); a
  different internal route + JWT -> 200 (JWT authorizer left on); that route + a
  well-formed *victim* id -> 200 (no ownership binding); the same with a
  destination field pointed at your own account -> the victim's object is now
  readable under your identity.
- Converts: **High** when a JWT-accepting route lacks the ownership check AND a caller-controlled destination exposes another account's object; **Medium** if only the authorizer gap is proven. Full method -> `../../broken-access-control/references/role-matrix.md` §2.

## Mobile cred chain: Firebase RemoteConfig + `alg:none` + hardcoded HMAC

Decompile -> Firebase key -> Firebase Remote Config -> base64 vendor secrets
(Azure `client_id`/`client_secret`, an HMAC signing key). Mint a vendor token
(Azure `client_credentials`), forge the API identity token as `{"alg":"none"}` with
an empty signature, and compute whatever signed request header the API requires (an
HMAC over the request with the leaked key). The only access control left is then
the object id.
- Recognize it: a mobile app pulling config from Firebase Remote Config; an API
  identity token that accepts `alg:none`; a custom HMAC-signed request header whose
  key ships in the client.
- Oracle ladder: Remote Config returns the secrets unauthenticated -> the forged
  `alg:none` token is accepted -> the HMAC header computes and passes -> the request
  succeeds and the only thing between you and another user's record is the object
  identifier.
- Rate it: **high** when the forged token + computed header leave only an object id
  as access control (chain to BOLA -> `idor-bola`). Full method -> `cognito-auth.md` F +
  `jwt-attacks.md` A.

## Body-field identity spoof

The endpoint carries the acting user's identity in the *body* (a field like
`userId`/`ownerId`/`author`/`userGUID`) and the handler trusts that field instead
of binding the action to the token's `sub`.
- Recognize it: an authenticated write (POST/PUT/PATCH) whose body names a
  user/owner. Lives in feedback/rating, comments, profile & preferences, "report
  abuse", share/invite, and on-behalf-of actions.
- Attack: replay your own authenticated request with that field swapped to a second
  account you control.
- Oracle ladder: no token -> 401/403 (signature enforced); own token + own id -> 200
  (baseline); own token + the other account's id -> 200/201 = bound to the body, not
  the token = spoof; well-formed nonexistent id -> no "not found" = no registry
  check; empty id -> 400 "missing field" = reads the body id, never cross-checks the
  sub; GET on the route -> 405 = write-only.
- Converts: **Medium** (attribution / metric / RLHF poisoning). Raise it only by proving the read side or a downstream routing effect (moderation / Trust-&-Safety queue). Method owned by `../../broken-access-control/references/graphql-api.md` §1; object half -> `idor-bola`.

## Tenant/org identifier trusted as a routing key

The server uses a tenant/org identifier taken from the request (a header, or a
path/body field) as a lookup/routing key and never verifies the caller's membership
in it.
> **Owner:** `../../tenant-isolation/references/tenant-vectors.md` §1 (read) and §2 (entitlement/cost twin).

- Recognize it: a request that carries an org/tenant id the caller supplies; the
  same object id returns different tenants' data as you vary that id.
- Oracle ladder: your token + your org id + object id -> 200 (baseline); your token +
  another org id + that org's object id -> full read = the id **routes**, it does not
  **authorize**; a wrong/garbage org id (even all-zeros) -> 404 (a routing miss, not
  an authz denial — the value is never validated); the **enforcing sibling** (a
  neighbouring route that returns 403 "not entitled") is the convincer that the gap
  is a bug, not the design.
- Same gap = entitlement bypass: a low-tier/consumer token + any tenant id drives
  paid compute (e.g. LLM inference) billed to the provider.
- Converts: **High** when the foreign-tenant response carries tenant-scoped business data or PII; **Medium** when it is non-sensitive metadata only; **Critical** when it reaches mass PII (an org user list, or 5–10 distinct bounded records).
- Cost-amplification twin — Converts: **High** — a documented entitlement gate plus quantifiable billed compute; it scores at or above the bare cross-tenant read. Method owned by `../../tenant-isolation/references/tenant-vectors.md` §2.

## Unauth API-GW -> DynamoDB, `ReturnValues` read side-channel

A config/telemetry `*.execute-api.<region>.amazonaws.com` maps POST/PUT/DELETE
straight through to DynamoDB with **no auth**, and `ReturnValues:"ALL_NEW"` /
`"ALL_OLD"` returns the full item — so you read even without a read endpoint.
- Recognize it: an unauthenticated API-Gateway host in the JS whose calls look like
  DynamoDB operations (an `X-Amz-Target` of `DynamoDB_*`, item-shaped bodies).
- Oracle ladder: an empty-body POST -> an **SDK validation error** (not a 401) = the
  route reaches the datastore with no auth in front; then `UpdateItem` with
  `ReturnValues:"ALL_NEW"` **on a sentinel item you created yourself** returns the
  whole item = read side-channel. **Do NOT use `DeleteItem` + `ALL_OLD` as the
  probe — it returns the item AND deletes it.** On a real record that is
  destruction of another user's data, not a read. Method and bounds are owned by
  `../../cloud-exploitation/references/dynamodb.md`.
- Rate it: **high** when unauth writes/reads reach a datastore holding real records.
  Cloud primitive -> hand to `cloud-exploitation`.

## Sequential object id as the only access control (BOLA)

A sequential identifier (an order/invoice/record id) is the only thing gating an
object — no ownership check behind it.
- Recognize it: an object endpoint whose id increments predictably and returns data
  for ids you were never granted.
- Oracle ladder: your own object id -> 200 (baseline); an adjacent id -> 200 with
  another user's data = no ownership check; confirm a **sibling** route enforces
  (403/404 on the same swap) to prove the gap is specific, not global.
- Converts: **not on its own** — chain to a PII read or a write, or find the enforcing sibling, before reporting. Hand the object primitive to `idor-bola`.

---

## Public-report auth-flow patterns (for classes not yet in the corpus)

- **OAuth code theft via open-redirect-on-allowed-host** — `redirect_uri` matches
  exactly but a `next=`/`returnUrl=` on that host forwards `?code=` off-domain ->
  exchange -> ATO. Method: `oauth-code-token.md` D.
- **JWT RS256->HS256 key confusion** — sign HS256 with the server's public JWKS
  key; forge any `sub`/`role`. Method: `jwt-attacks.md` B.
- **JWT `alg:none` / signature-not-verified** — byte-flip the sig; if still 200,
  edit claims freely. `jwt-attacks.md` A/E.
- **Password-reset host-header poisoning** — `X-Forwarded-Host: evil.com` puts the
  reset link on your host; victim click -> token -> ATO. `account-linking-recovery.md` A.
- **Pre-account takeover via social-login linking** — pre-create a password account
  on the victim email; their SSO links to it. `account-linking-recovery.md` G.
- **SAML XSW / cert-clone / comment-truncation** — impersonate an admin subject;
  the SP validates the signature over the original but reads your forged assertion.
  `saml-xsw.md` A/C/D.
- **MFA OTP not bound to user / response manipulation** — your OTP passes another
  user's challenge, or a flipped response promotes the session server-side.
  `mfa-session.md` A/C.
