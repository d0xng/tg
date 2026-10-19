---
name: auth-flow-bypass
description: "Hunt authentication-flow weaknesses in login, JWT, OAuth/OIDC, SAML, MFA/OTP, password reset, verification, account linking, mobile callbacks, and Cognito. Use when a target exposes sign-in or token issuance, authentication protocol endpoints, recovery flows, or client-side authentication configuration. This skill owns bypassing identity proof and forging credentials; route authorization failures after authentication to the access-control skills."
---

# Auth Flow Bypass

This skill covers bugs where authentication proof, session establishment, token
issuance, MFA, OAuth/OIDC, SSO/SAML, recovery, or an admin/ACL gate can be
forged or bypassed — and it exists to **prove the resulting impact**, not to
observe that a login page exists.

Use **this** skill when the question is "was this actor authenticated, verified,
or challenge-passed correctly, or can I mint/forge the proof myself?"

Once an actor is authenticated and the question is "can this role or object be
reached", the vector is owned by `broken-access-control` / `tenant-isolation` /
`idor-bola` per the owner table — this skill keeps only the token-minting/forgery
half.

## Where are you in the auth flow? (entry map — pick the line that matches, then open it)

Not a methodology; a router. Read it before the algorithm and jump straight to
the file that owns your position in the flow.

- **No account, no credentials, just a login page** -> `references/login-bypass.md`
  — beat the credential check itself (PHP type juggling / magic hashes, JSON
  `true`, content-type switching, verb tampering), then §E hands SQLi/NoSQLi to
  `../sqli`.
- **A login page and a username you believe exists** -> `references/login-bypass.md`
  §A2/§E first, then `references/account-linking-recovery.md` (reset/verify flows
  are a second door into the same account).
- **You hold a token/cookie already** -> `references/jwt-attacks.md` if it decodes
  as a JWT; `references/session-lifecycle.md` for how it is born and dies.
- **Logged in as low privilege, want more** -> this is no longer authentication:
  `../broken-access-control/references/role-matrix.md` (role/function gate),
  `../idor-bola` (object gate), `../tenant-isolation` (org/tenant gate).
- **MFA/OTP in the way** -> `references/mfa-session.md`.
- **SSO / SAML / OAuth in the way** -> `references/oauth-code-token.md` (OAuth/OIDC),
  `references/saml-xsw.md` (SAML), `references/cognito-auth.md` (Cognito).
- **A reset link, magic link, invite or verification email** ->
  `references/account-linking-recovery.md`.
- **An admin portal, proxy/cache manager or ACL-gated internal page** ->
  `references/acl-proxy-cache.md`.
- **A guest/anonymous token or a hardcoded auth key in the JS** ->
  `references/cognito-auth.md` §E, then `../broken-access-control/references/role-matrix.md` §1.

## Impact-first mandate (read every session)

A reachable admin endpoint, a decodable JWT, a redirect that reflects a
parameter, a reset email that arrives — **none of these are findings**. The
finding is the *proven* account takeover, cross-tenant read, admin data pull, or
credential mint. Discovery is rung 0.

**Import the shared foundation and climb it — do not re-invent a "keep it
passive" rule:**

- `../_shared/references/safe-ladder.md` — the ONLY escalation policy. Read-only
  first -> own/anonymous context -> minimal (one record) -> UAT for risky proof
  -> writes/other-user data on prod require d0x's approval before execution, not attempted. Every "passive / status,
  title, version only / don't call it" instinct is wrong: replace it with the
  lowest rung that *proves the class*.
- `../_shared/references/public-by-default-keys.md` — when a key surfaces in an
  auth flow, resolve SKIP vs PURSUE here. A reCAPTCHA site key or Stripe `pk_` is
  SKIP-silent; a **hardcoded guest/auth API key**, a Cognito client secret, or an
  Azure `client_secret` is PURSUE — it *is* the primitive.

Nothing will stop you: the rung is decided before the request is built, by
reading the ladder, and no guard fires afterwards to say a line was crossed. When
a step would be rung-3-on-prod / other-user PII / a write, drop to the non-PII
read on prod, or run the full cross-tenant/ATO proof on UAT — do not stop hunting.

## Read-On-Demand References

- `references/login-bypass.md` — the credential check itself, before any token
  exists: PHP type juggling and magic hashes (`0e`-form md5/sha1, and exactly
  which juggles PHP 8 killed), `json_decode` type confusion
  (`{"password":true}`, `in_array(true,…)`), `password[]=` array injection,
  content-type / format switching (JSON <-> form <-> XML <-> multipart, and the
  XML branch opening XXE), verb switching on the auth endpoint, and the honest
  self-exploitation caveat on response manipulation. Open it the moment a login
  form or credential endpoint is in front of you — before you have any token to
  forge. SQLi/NoSQLi on the login is recognition-only there and hands to `../sqli`.
- `references/jwt-attacks.md` — the JWT forgery ladder: `alg:none`, RS256->HS256
  key confusion, `kid` path-traversal / SQLi / command injection, `jku`/`x5u`/`x5c`
  header injection (JWKS spoof), null-sig, claim/`sub` swap, weak HMAC crack.
- `references/cognito-auth.md` — AWS Cognito auth-abuse: `aws.cognito.signin.user.admin`
  self-writable `custom:*` tenant attrs, dual-authorizer admin API Gateways,
  self-signup / `UserConfirmed:true`, identity-pool unauth IAM creds (credential-free
  `cognito-identity` `GetId`/`GetCredentialsForIdentity` curls), guest/anon token ->
  an admin namespace. The WAF-origin bypass it routes to is owned by
  `../broken-access-control/references/role-matrix.md` §1.
- `references/oauth-code-token.md` — OAuth/OIDC: `redirect_uri` bypass ladder,
  `response_type`/`response_mode` downgrade, PKCE downgrade/strip, code & token
  replay/expiry, client binding, `state`/`nonce`, and code-exfil chains.
- `references/mfa-session.md` — 2FA/MFA: response manipulation, step skipping,
  OTP-not-bound-to-user, no-rate-limit reuse, backup-code reuse, remembered-device
  forgery, MFA-disable without re-auth, and session promotion.
- `references/session-lifecycle.md` — session fixation (no rotation on login or
  on privilege elevation) and session invalidation (logout, password change /
  reset / email change, refresh-token & OAuth-grant survival of a revoke, the
  active-devices inventory gap, remember-me persistence, JWT revocability and
  `exp` window). Owns SESSION lifecycle for the whole pack; ships a local
  `python3` harness to calibrate the capture/replay mechanics. Every proof is
  rung 2 on the operator's own account.
- `references/account-linking-recovery.md` — password-reset arsenal (host-header
  poisoning, token via IDOR/Referer, token reuse/predictability, array/param
  pollution), email verification, social-login linking, pre-account takeover.
- `references/saml-xsw.md` — SAML XML Signature Wrapping (XSW1-8), signature
  stripping, comment-truncation (CVE-2017-11427 class), audience/recipient
  confusion, IdP-initiated to arbitrary SP, XXE in SAMLResponse.
- `references/acl-proxy-cache.md` — admin login bypass, reverse-proxy / cache-manager
  ACL differentials, localhost/internal ACL bypass.
- `references/case-patterns.md` — generalized auth-bypass technique patterns with
  per-class "converts to <sev> when" guidance.
- `references/plays.md` — the six plays as they ran in **d0x's own reports of this
  class**, with outcomes. A third of them did not convert, and neither failure was
  technical: one on proof shape, one on venue. Read it before planning the proof.
- `references/case-index.md` — those six by play, host, severity and state, with
  corpus paths.
- `../_shared/references/output-contract.md` — where results go: the
  notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim`
  dedup key, and the severity enum.
- `../_shared/references/tooling.md` — what is installed on this host, what is
  not, and the install line for each missing binary.

## Triggers

- **a login / credential endpoint at all** — `/login`, `/signin`, `/api/auth`,
  `/session`, an `/oauth/token` password grant, an admin portal's form: the
  credential *check* is a target before any token exists ->
  `references/login-bypass.md`;
- a **PHP** fingerprint — `X-Powered-By: PHP`, a `PHPSESSID` cookie, a `.php`
  path, or a parameter name whose `.`/space/`[` came back as `_` — makes the
  type-juggling and magic-hash ladder live -> `references/login-bypass.md` §A;
- an auth endpoint that accepts **more than one body format** (JSON and form,
  or an XML/SOAP sibling), or whose validator behaves differently per
  `Content-Type` / per HTTP verb -> `references/login-bypass.md` §B/§C;
- a **JWT** anywhere (cookie, `Authorization: Bearer`, `id_token`, `access_token`,
  URL fragment) — decode the header first; alg/kid/jku are the attack surface;
- a **mobile app** whose OAuth callback is an **exported activity** on a custom
  URI scheme, or a client secret shipped in the package — the callback is a remote
  entry point and the code can be injected -> `references/oauth-code-token.md` §H;
- `/oauth/authorize`, `/oauth/token`, `/callback`, `/login/oauth/*`, `/oidc/*`,
  `/connect/*`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`;
- `/saml/*`, `SAMLResponse`, `SAMLRequest`, `<saml:Assertion>`, ADFS/Okta/OneLogin;
- a **Cognito** signal: `cognito-idp.<region>.amazonaws.com`,
  `cognito-identity.<region>.amazonaws.com`, a `us-east-1_XXXX` pool id, an
  `AWSCognitoIdentityProviderService.*` `X-Amz-Target`, a JWT `iss` of
  `cognito-idp.*`, `scope: aws.cognito.signin.user.admin`;
- MFA/2FA challenge APIs, `mfa_required`/`otp`/`totp`, remembered-device cookies,
  backup/recovery codes, "verify 2FA" responses;
- password reset, email verification, invite acceptance, `email` change, social
  login, account linking;
- **any session at all** — a `Set-Cookie` on login, a logout endpoint, an "active
  devices / sessions" page, a "sign out of all devices" button, a "remember me"
  checkbox, a `refresh_token`, or a long-`exp` JWT -> `references/session-lifecycle.md`;
- a **guest/anonymous login** (an anonymous/guest token endpoint), a hardcoded
  auth key in JS, or an admin/management route group;
- admin login portals, customer-lookup tools, proxy/cache manager endpoints,
  ACL-gated localhost/internal resources.

## Safety Rules (recalibrated to the safe-ladder — NOT "stay passive")

The safe-ladder is the safety policy. It keeps proofs read-only / own-context /
UAT so they neither harm the target nor trip the classifier — while still
**reaching impact**. Concretely, for this skill:

- **Forge and USE the token.** Minting an `alg:none`/key-confusion JWT and then
  calling a protected `/me`, `/api/config`, or `GetUser` with it — that read is
  the deliverable, not a side effect. "I can decode the JWT" is rung 0.
- **Own/anonymous context for the swap.** Prove cross-user/cross-tenant with two
  accounts *you* created (or an anonymous token where anonymous IS the bug).
  For a Cognito `custom:*` tenant-attribute overwrite, point it at your **own**
  second org's UUID, read it back, then **revert the attribute immediately**.
- **Prove the scale, don't hoard it.** One cross-tenant record, one victim reset token
  (delivered to *your* mailbox in a two-inbox test), one admin object proves the
  class. Never dump an admin user-list endpoint in full — read one row, state scale
  by inference.
- **UAT for the risky rung.** If RoE restricts cross-tenant/PII proof to
  `*-uat`/`*-oat`, run the full ATO/cross-tenant proof there and state the
  prod-equivalent by inference (safe-ladder rung 4).
- **Do NOT brute force** OTPs, backup codes, reset/auth-code tokens, or sessions
  — that is destructive volume, not a proof. *Do* prove no-rate-limit / reuse /
  predictability with a handful of requests, or that a single valid value is
  accepted out of context.
- **Password change, 2FA disable, email change, or reading a REAL user's data on
  prod -> not attempted: ask d0x directly before executing** carrying the exact request. Prefer proving
  it on your own second account or on UAT so this rung is never needed.
- **Flag every forged/leaked credential you exercised for rotation** in the lead
  file you write under `targets/<program>/leads/`.

## Algorithm

1. **Decode everything first.** Any JWT -> split it, base64url-decode the header
   and payload. Header `alg`/`kid`/`jku`/`x5u`/`x5c` -> `references/jwt-attacks.md`.
   `iss: cognito-idp.*` or `scope: aws.cognito.signin.user.admin` ->
   `references/cognito-auth.md`. This is a reflex on every session.
2. **Map the flow.** Actors, sessions, clients, redirect URIs, tokens, expiry,
   challenge state, the tenant/org claim, and the one-time / boundary invariant
   each step relies on.
2b. **Attack the credential check itself — before you have any token to forge.**
   The login form is a target, not just a way in. Fingerprint the stack (the
   `?user.name=` mangling probe), then run
   `references/login-bypass.md`: PHP type juggling and magic hashes, the
   `{"password":true}` JSON type confusion, the content-type ladder, the verb
   ladder. Cheap — one request per rung, all rung 1-2 — and it is the only
   angle available when `accounts.md` is empty.
3. **Baseline.** Complete the normal flow with an operator account and capture
   every request/response.
4. **Session-lifecycle sweep — on every target that has a login.** The baseline
   in step 3 already handed you the session; before mutating anything, spend the
   four requests that ask whether that credential is *born* and *dies* correctly:
   is the pre-auth identifier rotated at login, does logout kill it server-side,
   does a password change kill the *other* sessions, does the refresh token still
   mint after a revoke. Open `references/session-lifecycle.md` for the
   procedures, oracles, negative controls and per-item Converts verdicts (and its
   local harness when the capture/replay mechanics need calibrating first). This
   is entirely rung 2 on the operator's own account — no second user, no victim —
   so there is never a reason to skip it.
5. **Mutate one invariant at a time.** Forge the JWT; replay/expire the code;
   swap `redirect_uri`/`response_type`; drop PKCE; skip the MFA step; poison the
   reset `Host`; overwrite the Cognito attribute; wrap the SAML assertion; hit
   the guest token against the admin namespace.
6. **Confirm server-side.** A changed UI flag or a 200 title is NOT the proof.
   The forged token must return protected data; the swapped id must return the
   other tenant's record; the reset must grant login. Climb the safe-ladder
   until that read/action succeeds.
7. **Dedup.** The `references/case-patterns.md` entries are reusable techniques, not
   detectors — reuse the technique, but novelty-check the candidate before
   promoting. Dedup before you call it new:
   `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`,
   and — when the program has one — its live ledger under
   `targets/<program>/reports/`, which wins over any stale export. A match on the
   same primitive + same host is CLOSED: rotate to the next angle.
8. Hand ATO / auth-bypass / token-mint / cross-tenant claims to `validation`,
   then `report-writing`. Write the lead to `targets/<program>/leads/` in the
   format in `../_shared/references/output-contract.md`.

## Confirmation Oracles

Strong (climb to the read/action and capture it):

- the login succeeds with a value that is not the password — a magic-hash string,
  a JSON `true`, an operator object — while a wrong string in the identical
  request still fails, and the resulting cookie/token returns data from a
  protected route -> `references/login-bypass.md`;
- the identical credential authenticates under one `Content-Type` or one HTTP
  verb and is rejected under another (a validator blinded, not just a different
  error message) -> `references/login-bypass.md` §B/§C;
- forged JWT (`alg:none`, HS256-with-public-key, `kid` traversal, `jku`/`x5c`
  spoof, `sub` swap) is accepted on a protected route -> returns data;
- Cognito `UpdateUserAttributes` on the tenant-bearing `custom:*` attribute succeeds ->
  re-auth mints a JWT with the forged tenant claim -> tenant-scoped endpoint
  returns the other org's data;
- guest/anonymous/credential-free token returns data from an admin/management route group;
- dual-authorizer: a plain Cognito `id_token` is accepted on an IAM-scoped admin
  gateway route with a user-controlled destination -> victim object copied/read;
- reset link built with attacker `Host`/`X-Forwarded-Host`, or reset token
  returned in an API response / leaked via Referer, or an old token still works;
- same authorization code mints two valid tokens; expired code accepted; token
  exchanges with wrong `redirect_uri`/client/no PKCE verifier;
- MFA-gated route succeeds before verification, or one OTP/backup code passes a
  *different* user's challenge, or the OTP has no rate limit and is reusable;
- SAML with a wrapped/stripped signature or truncated-comment `NameID` is
  accepted and authenticates as another subject;
- a pre-auth session identifier is unchanged after login and returns
  authenticated data, or a captured session/refresh token still returns account
  data after a timestamped logout / password change / reset / revoke —
  `references/session-lifecycle.md`;
- a sibling/canonical flow *enforces* while the alternate endpoint succeeds
  (the "sibling enforces correctly" convincer).

Weak (rotate the angle, don't report):

- UI shows "logged in" but the canonical protected route still 401s;
- a flipped `{"success":true}` / `401`->`200` in your own browser with no
  server-side consequence — self-exploitation, closes as informative
  (`references/login-bypass.md` §D);
- `password[]=` returns a `500`/`TypeError` — a PHP-8 fingerprint, not a bypass;
- a different validation *error message* per `Content-Type` with the auth
  outcome unchanged;
- one endpoint returns `mfa_required` but the protected route denies;
- a short-`exp` access token replayed inside its own documented window, or "a
  stateless JWT cannot be revoked" with no invalidation event behind it;
- `redirect_uri` accepted only for the exact registered safe URL;
- 404/403 on a swapped id (authz working);
- expired/reset token cleanly rejected.

## Evidence to capture

Raw proof (decoded JWTs, forged token headers, `GetUser` output, the cross-tenant
response, the poisoned-link capture, the SAML assertion) goes to
`targets/<program>/notes/`; the promoted bug to `targets/<program>/findings/` —
see `../_shared/references/output-contract.md`. Redact victim PII, keep
identifiers in `id=<n>`/uuid form, and keep the request/response bytes raw: a
paraphrased response is not evidence.

- the actor / client / session / tenant matrix — which accounts, which claim,
  which token;
- the exact endpoint and flow step, plus the decoded token or assertion
  (signature redacted);
- the invariant that was supposed to hold: single-use code, verified signature,
  MFA required, verified email, exact `redirect_uri`, admin-write-only attribute,
  ACL required;
- the baseline request/response from the canonical flow;
- the ONE mutated request/response — the forge or bypass;
- **the protected resource / session / token / cross-tenant read that proves
  server-side impact** — the climb, not the discovery (one record, PII redacted);
- a negative control: the canonical flow denies, or an enforcing sibling route
  exists;
- the safe-ladder rung reached, every revert performed (Cognito attribute, MFA
  re-enable, own-account password), and a rotation flag for every forged, leaked,
  or exercised credential.

## Severity Guidance

- low: weak auth metadata or flow inconsistency with no session/data impact.
- medium: limited token/session reuse or MFA/state inconsistency on an owned
  account; write-only body-field identity spoof (this pattern caps here);
  session fixation with a stated planting vector; a session surviving logout.
- high: JWT forgery accepted on a protected route, MFA bypass, admin auth bypass,
  reusable OAuth code/token with real scopes, dual-authorizer cross-account read,
  account-linking into another controlled account; a session or refresh token
  surviving a password change/reset (the victim's own remediation fails).
- critical: full account takeover, no-interaction password reset, cross-tenant
  read/write via Cognito attribute or org-header spoof, SAML XSW impersonation,
  privileged OAuth credential minting, broad admin-namespace PII exposure.

### What d0x's own reports in this class actually did

Full write-ups in `references/plays.md`; the index in `references/case-index.md`.
Two of six did not convert and **neither failed on the technique**:

**Plan the last step of the proof onto an account you control.** An OTP report — no
rate limit, no lockout, 30-minute validity, unarguable arithmetic — came back
*informative* because the takeover was never completed against a real account, which
would have needed a stranger's phone. Brute-force **your own** number, complete the
takeover on **your own** account, then state the victim case by inference. Same
evidence, and it becomes a demonstration instead of a calculation.

**Check the program's excluded classes at DISPATCH.** A signature-counting flaw that
halved a Byzantine threshold — the strongest pure analysis in the corpus — was filed
somewhere that does not buy that class.

**Decode the token before touching the target.** Two of the six turned entirely on what
the token itself carried: the identity-provider pool and client ids from `iss` and
`client_id`, and the self-administration scope from `scope`. Zero requests to the
target, and it is what made the tenant bypass findable at all.

**Enumerate what the session reaches.** The least technical finding in the corpus — a
default `admin`/`admin` — scored Critical because the report counted 649 dashboards,
31 datasources, six staff admin accounts, and named the specific admin operations
available. The bypass opens a report of this class; it never closes it.

**A non-production hostname discounts the finding even when the data is production.** A
staff tool that queried the live reservation system and returned real passengers'
contact details still sat at P3. When the data is production, say so in the title.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- `cloud-exploitation`: a Cognito/identity-pool/execute-api marker resolves to a
  cloud CRUD/creds primitive (hand off the pool id + client id + JWT).
- `exposed-secrets`: a PURSUE key (hardcoded guest key, Cognito client secret,
  Azure `client_secret`) needs its own service-API proof.
- `idor-bola` / `broken-access-control`: object ownership is the core primitive once
  authenticated — `idor-bola` for "same endpoint, same role, different id, no
  ownership check", `broken-access-control` for a missing function-level decision
  (role, admin namespace, gateway authorizer, plan gate).
- `broken-access-control` (lifecycle split): the credential outliving the event
  is a **session** question — rotation, logout, password change, revoke, device
  list — so it stays here in `references/session-lifecycle.md`. When instead a
  **role, seat, plan, membership or grant** was removed and the old credential
  still works, that is
  `../broken-access-control/references/lifecycle-persistence.md`.
- `tenant-isolation`: the forged claim crosses an **org/workspace/tenant** line —
  the Cognito self-writable `custom:*` chain and tenant/org-header routing are
  owned there.
- `ssrf-safe`: a `jku`/`x5u`/SAML metadata URL is your SSRF sink.
- `validation` -> `report-writing`: after the server-side proof holds.
