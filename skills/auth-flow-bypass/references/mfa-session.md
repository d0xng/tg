# MFA Bypass & Session Promotion

## Contents
- Invariants (each is a bypass when missing)
- A — Response manipulation (server must ignore it)
- B — Step skipping / forced browsing
- C — OTP not bound to the challenged user
- D — No rate limit / reuse / weak OTP (no brute force)
- E — Remembered-device / trust cookie
- F — MFA disable / method change without re-auth
- Good evidence
- False-positive gates (rotate, don't report)
- Ladder discipline

Use for 2FA/MFA (TOTP, SMS, email OTP, push, WebAuthn), backup codes, remembered
devices, recovery, session upgrade, and response manipulation. The finding is **a
fully-authenticated session reached without the second factor** (or with a factor
that isn't yours), proven on a protected server route — not a flipped UI flag.
Prove it on your **own** MFA-enabled account (rung 2); do **not** brute-force
OTPs.

## Invariants (each is a bypass when missing)

- a password-only session stays half-authenticated until MFA is verified
  **server-side**; protected routes reject it;
- client response flags never control MFA completion;
- an OTP/backup code is bound to the *challenged user*, single-use, expiring, and
  rate-limited;
- remembered-device / recovery cookies are bound to user + device + expiry +
  challenge state;
- disabling MFA / changing the MFA method requires a fresh factor.

## A — Response manipulation (server must ignore it)

Complete password step, capture the MFA-verify response, then flip it and see if
the **server** promotes the session:

- body `{"success":false}` -> `true`, `{"mfa":"required"}` -> `"passed"`,
  `{"error":...}` -> `{}`; status `401`/`403` -> `200`;
- some SPAs gate purely on the response — after the flip, the app sets a full
  session cookie / stops re-challenging. **Confirm on a canonical protected API
  route**, not the UI. If the route still 401s, it's a weak signal — rotate.

## B — Step skipping / forced browsing

- After the password step returns a "go to MFA" state, request the **post-login**
  endpoint directly (`/dashboard`, `/api/me`, `/api/account`, the OAuth
  `/authorize` continue URL). If it serves authenticated data, MFA is a
  client-side gate only.
- **Endpoint/flow asymmetry** — the web flow enforces MFA but the **mobile/API/
  legacy** flow (`/api/v1/login`, `/oauth/token` password grant, a partner SSO
  entry) doesn't. The convincer: a *sibling* flow enforces while the
  alternate mints a full session.
- **Registration/OAuth path** — signing in via social/SSO or a fresh signup that
  links to the MFA-protected account sometimes lands post-MFA.

**The pre-account variant: a multi-step onboarding wizard.** There is no session to
promote here — the flow advances an *application* record (`party`, `application`,
`case`) through steps, and email/SMS verification is one of them. Same defect,
different surface, and it is missed because there is nothing that looks like a
login to attack.

- The static tell is in the bundle: step routes with **no route guard**, advanced
  by a `router.navigate()` fired on a `200` from the verify call. The greps are in
  `../../js-source-to-sink/references/code-sinks.md` §4.
- **The proof is the next step's endpoint, never the client.** Patching XHR in your
  own console so the SPA believes the OTP verified is a *discovery* shortcut, and
  on its own it is self-exploitation — the same closure `login-bypass.md` §D
  describes. What converts it: after the client advances, call the **subsequent
  step's API directly** with the application id and show the server accepts it
  without ever having recorded the verification. Lead the report with that request,
  not with the console snippet.
- Ask the corroborating question in the report: does *any* server response before
  the final submission reflect a `verified` state? If nothing does, the server
  never had the state to check — say so; it converts a "bypass" into a missing
  server-side state machine, which is harder to argue away.

**Corpus case:** `3859969` — `h1/reports/3859969-equitable-bank-duplicate.md`
(high · duplicate; onboarding wizard, both OTP steps skipped).

## C — OTP not bound to the challenged user

A high-impact MFA bug: an OTP/backup code from **your** account passes
**another** user's challenge (server checks "is this a valid code?" not "is this
*their* code?").

1. Start victim's login to the MFA challenge (using your own second account as
   the "victim" — own-context).
2. Submit *your own* freshly-generated OTP/backup code against that challenge.
3. Session promoted = the code isn't user-scoped. Prove with your two accounts.

## D — No rate limit / reuse / weak OTP (no brute force)

> **On a GraphQL endpoint, count operations rather than requests.** Alias batching
> puts N verification attempts inside ONE HTTP request, so a lockout or rate limit
> that counts requests never fires — and that is a *bypassed control*, which is a
> finding, unlike a merely absent one. Prove it with the sequential-vs-batched
> differential and a bounded N, never by exhausting a real factor:
> `../../graphql/references/batching-abuse.md`.


You do **not** brute-force. You prove the weakness with a handful of requests:

- **Reuse**: submit an already-used OTP/backup code again -> accepted = not
  single-use.
- **No expiry**: use an OTP well past its window -> accepted.
- **No rate limit**: send ~10 wrong codes and observe the response never changes
  to a lockout/`429` and the counter never trips — that *demonstrates* the
  control is absent without exhausting the keyspace. State the brute-forceability
  by inference (6-digit / 10^6, no lockout), do not actually run 10^6.
- **Predictable**: OTP derived from timestamp/sequence, or the SMS/email code
  echoed in an API response (`{"otp":"482913"}`) or a header — that's an instant
  bypass, capture it.
- **Backup codes** predictable / reusable / generated on a guessable seed.

## E — Remembered-device / trust cookie

- Is the "remember this device" cookie/token **portable** — does it work from
  another browser/session/account? Transferable = forgeable trust.
- Is it deterministic (userid + secret with a weak/known secret)? Then it's
  forgeable — try minting one for your second account.
- Does it survive password change / MFA reset (should be revoked)? The
  invalidation half of that question — and the persistent **authentication**
  cookie's own lifecycle — is owned by `session-lifecycle.md` §G.

## F — MFA disable / method change without re-auth

- `POST /api/2fa/disable` (or remove-phone, change-method) that succeeds with
  just the session cookie and **no fresh factor** = an ATO amplifier: any session
  hijack becomes permanent MFA removal. Prove on your own account, then
  **re-enable MFA** (revert).
- IDOR/CSRF on the disable endpoint (`{"user_id":<victim>}`) -> disable another
  user's MFA. Own-context only.

## Good evidence

- protected server route returns authenticated data before MFA verification;
- full session cookie issued after a response flip (server-side, canonical route);
- your OTP/backup code passes your second account's challenge (not user-bound);
- an OTP is reused / accepted past expiry / echoed in a response;
- ~10 wrong OTPs with no lockout/`429` (rate-limit absent), impact by inference;
- remembered-device cookie works cross-session/account;
- MFA disabled with only a session and no fresh factor (then re-enabled).

## False-positive gates (rotate, don't report)

- only the frontend changes; the canonical protected route still denies;
- the promoted session can view only MFA-setup/challenge pages;
- program documents the password-only session as intentionally limited;
- a single wrong-code `429` on the first retry = rate limit IS present.

## Ladder discipline

Own MFA-enabled accounts only. Never brute-force to exhaustion, never target a
real user's device/number. Reading a real user's data or disabling a real user's
MFA on prod = ask d0x directly before executing; prove with your two accounts or on UAT. Revert any
disable/method change immediately.
