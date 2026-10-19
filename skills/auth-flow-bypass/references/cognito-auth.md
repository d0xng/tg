# Cognito & Token-Gated Auth Abuse

## Contents
- Markers -> which attack
- A — Self-writable custom attributes -> tenant-isolation bypass
- B — Dual-authorizer admin API Gateway (HIGH)
- C — Identity-pool unauth IAM credentials
- D — Self-signup / confirmation bypass (enabler)
- E — Guest / anonymous token reaching an admin namespace (+ WAF-origin bypass)
- F — `alg:none` / hardcoded HMAC in a mobile cred chain
- Proof to capture

AWS Cognito and "any-valid-token" gateways are high-yield auth-bypass surfaces.
The markers are cheap to spot; the finding is the **cross-tenant / admin read you
reach with a token you legitimately minted or forged**. Climb the safe-ladder
(`../../_shared/references/safe-ladder.md`) — read-only, own-context, revert any
attribute write immediately.

Hand a resolved cloud primitive (identity-pool IAM creds, execute-api CRUD) to
`cloud-exploitation`. Dedup before you call it new:
`rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`,
and — when the program has one — its live ledger under
`targets/<program>/reports/`, which wins over any stale export. A match on the
same primitive + same host is CLOSED: rotate to the next angle.

## Markers -> which attack

| Signal | Attack |
|---|---|
| JWT `iss: cognito-idp.<region>.amazonaws.com/<pool>` | pool + client id recoverable; go A/B |
| access token `scope: aws.cognito.signin.user.admin` | **A** — self GetUser/UpdateUserAttributes |
| backend authorizes tenancy from a `custom:*` attribute (`custom:tenantId`/`custom:orgId`/`custom:domain`) | **A** — overwrite the tenant claim |
| a *second* `*.execute-api.<region>.amazonaws.com/<stage>` in JS, admin-ish routes | **B** — dual authorizer |
| `cognito-identity.<region>.amazonaws.com`, identity-pool id `region:uuid` | **C** — unauth IAM creds |
| self-signup returns `UserConfirmed:true` / no email step | **D** — signup bypass lowers the bar |
| guest/anon login token, hardcoded key in JS, an admin/management route group | **E** — guest -> admin (+WAF origin) |

Recover pool + client id from the JWT: `iss` path segment = user-pool id;
`client_id` claim (access token) or `aud` (id token) = app client id; region is
in the host.

## A — Self-writable custom attributes -> tenant-isolation bypass

If the access token carries `scope: aws.cognito.signin.user.admin`, the user may
call the Cognito user API **directly** and edit their own attributes. If the pool
did not mark the tenant-bearing attribute admin-write-only, overwrite it, re-auth
to mint a JWT with the forged claim, and read the other tenant's data.
`custom:<tenantAttr>` is a placeholder — read the real attribute name off
`GetUser`; the Cognito API calls themselves are identical for every account.

> **Owner:** the full AWS API sequence (`GetUser` → `UpdateUserAttributes` → `InitiateAuth`, pool/client recovery from the JWT, the revert) lives in `../../cloud-exploitation/references/cognito.md` §5c. The tenant chain — what to read and what proves it — is `../../tenant-isolation/references/cognito-takeover.md`. This card keeps only the recognition signal, the oracle, and the verdict.

Oracle: `GetUser` lists the tenancy attribute in your **writable** set → `UpdateUserAttributes` returns 200 → re-auth mints a JWT carrying the forged claim → a tenant-scoped endpoint returns the OTHER org's records. The 200 alone is N/A.

Victim org UUIDs are not secret — avatar/asset CDN paths keyed by org id, other members' JWTs, same-email-domain auto-assign, public team/roster endpoints. Full list: `../../tenant-isolation/references/oracles-and-leaks.md`.

**Rungs for this chain (identical in every copy):**
1. `GetUser` on your own access token — **rung 1** (read-only).
2. `UpdateUserAttributes` on your own Cognito profile — **rung 2**. The write mutates *your* account, never the victim's; revert it the moment the read is demonstrated.
3. The VALUE you write decides the rung of the *proof*, not of the write:
   - **a second org YOU own → rung 2. This is the default and the preferred proof.** Seed one (self-signup; `UserConfirmed:true` lowers the bar) before reaching for a real org id.
   - **a real victim org UUID on a UAT/OAT host (`*-uat`, `*-oat`, `api-qa.*`) → rung 4.** Use this when the app will not let you create a second org.
   - **a real victim org UUID on prod → rung 5 — not attempted**: ask d0x directly with the exact request before executing. Prefer stating prod impact by inference from the rung-2/rung-4 proof so this rung is never needed.
4. `UpdateUserAttributes → 200 {}` is **N/A on its own** — the finding is the end-to-end cross-tenant READ after re-auth.

Converts: **Critical (P1)**. The `UpdateUserAttributes` 200 alone is N/A.

## B — Dual-authorizer admin API Gateway (HIGH)

JS reveals a *second*, internal `*.execute-api.<region>.amazonaws.com/<stage>`
distinct from the main API. Most routes reject a Cognito JWT with
`"Credential should be scoped to a valid region"` (they expect IAM SigV4) — but a
few were mistakenly left on a **Cognito JWT authorizer**, and the Lambda behind
them does **zero ownership** check on the id in the path/body.

> **Owner:** `../../broken-access-control/references/role-matrix.md` §2 owns the method (route bucketing, the copy/clone destination-field attack, the enumeration-route id resolution).

Recognize it here: two distinct `*.execute-api` hostnames in the JS; on the internal one, most routes reject a plain Cognito `id_token` with `"Credential should be scoped to a valid region"` while a few return 200.

Converts: **High** when a JWT-accepting route lacks the ownership check AND a caller-controlled destination exposes another account's object; **Medium** if only the authorizer gap is proven.

## C — Identity-pool unauth IAM credentials

`cognito-identity.<region>.amazonaws.com` + an identity-pool id (`region:uuid`)
that allows **unauthenticated** identities = temporary IAM creds for anyone.

```bash
CIDENT=https://cognito-identity.<region>.amazonaws.com/
ID=$(curl -s "$CIDENT" -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'X-Amz-Target: AWSCognitoIdentityService.GetId' \
  -d '{"IdentityPoolId":"<region>:<uuid>"}' | jq -r .IdentityId)
curl -s "$CIDENT" -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity' \
  -d "{\"IdentityId\":\"$ID\"}"     # -> AccessKeyId/SecretKey/SessionToken
# `aws` CLI absent, but boto3 (1.43.18) is present and signs SigV4 — use the
# python3 -c "import boto3..." form; see ../../_shared/references/tooling.md
aws sts get-caller-identity            # rung-1 proof of the granted role
```

Then hand the creds to `cloud-exploitation` (`../../cloud-exploitation/references/iam-creds.md`) — enumerate the
attached policy read-only; `sts get-caller-identity` is the finding, do not
mutate real infra. Flag the identity pool for rotation.

## D — Self-signup / confirmation bypass (enabler)

`SignUp` returning `UserConfirmed:true`, or a confirmation step you can skip,
lowers the bar for A/B (you get a real token without an invite). Sign up an
attacker-controlled account, confirm it's usable, then run A/B. This is an
*enabler*, not the finding on its own — the finding is what the token then reads.

```bash
CIDP=https://cognito-idp.<region>.amazonaws.com/
curl -s "$CIDP" -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'X-Amz-Target: AWSCognitoIdentityProviderService.SignUp' \
  -d "{\"ClientId\":\"$CLIENT\",\"Username\":\"you+poc@you.com\",\"Password\":\"P0c!pass1\",\"UserAttributes\":[{\"Name\":\"email\",\"Value\":\"you+poc@you.com\"}]}"
```

## E — Guest / anonymous token reaching an admin namespace (+ WAF-origin bypass)

A guest/anonymous login (or a hardcoded auth key in the JS) returns a *usable*
token, and an admin/management route group enforces **no role** — any valid token
is accepted.

Converts: **Critical** when the admin group returns cross-user PII; **High** when it returns non-PII privileged data. The reachable route alone is not a finding.

Method (locate the actual guest-login endpoint, key, and admin routes on the
target — these are app-specific, the technique is not):

1. Mint the guest/anonymous token. The unlocking key is often a **hardcoded auth
   key in the JS** (a PURSUE primitive) sent as an auth header to a public
   guest/anonymous login endpoint; the response carries a bearer token (`$GUEST`).
2. Replay `$GUEST` against the admin/management route group — the routes that serve
   cross-user or back-office data (user directories, support/contact messages,
   uploaded files, back-office records). Read ONE record.
3. Oracle: no token -> 401/403; `$GUEST` on a normal user route -> 200 (token
   valid); `$GUEST` on an admin route -> 200 with cross-user data = no role gate.

**WAF-origin bypass:** if a CDN/WAF blocks the admin path at the edge but the origin serves it, recover the origin IP and dial it directly — method owned by `../../broken-access-control/references/role-matrix.md` §1 ("WAF-origin bypass"). Read one row per admin route, note sequential ids for per-record IDOR, and state "N admin routes / N records exposed" by inference — never paginate the table.

## F — `alg:none` / hardcoded HMAC in a mobile cred chain

> **Tooling:** `jadx` and `apktool` are installed but **not on PATH** — call them by absolute path: `~/tools/jadx/bin/jadx -d out/ app.apk`, `~/tools/bin/apktool d app.apk`.

Mobile targets: decompile -> Firebase Remote Config secrets -> Azure/Auth0 tokens,
and the API identity token often accepts `{"alg":"none"}` with an empty sig. Forge
the identity token (see `jwt-attacks.md` rung A), compute any required signed
request header (an HMAC over the request with the leaked key), then the only access
control left is the object id (BOLA — `idor-bola`). Firebase Remote Config secret mining
+ `alg:none` are high-yield first moves on any mobile target.

## Proof to capture

Decoded JWT (scopes/iss/client), the exact service-API call + response, the
cross-tenant/admin **read of one record** (PII redacted), a negative control (an
enforcing sibling route, or the same call before the attribute overwrite), the
`custom:*` revert confirmation, and a rotation flag for every credential touched.
