# The plays — authentication flow bypass

Built from 6 of d0x's own reports across `auth-bypass`, `auth-rate-limit` and `sig-verification`. A small sample, and unusually informative *because* it is small: two of the six did not convert, and the reasons are precise.

**1 Critical triaged · 1 P1 · 2 P3 unresolved · 1 Critical claimed → informative · 1 not-applicable.**

Refs point at `~/Desktop/skills/personal-corpus/`.

---

## 1 · The token-issuing endpoint that asks for nothing

> **Shape.** An internal or staff-facing tool needs a session before it can be useful, so it has a login. That login validates *context* — a location code, a device id, a kiosk number — rather than *identity*, and hands out a real token to anyone who supplies plausible context.

**b58ed2d07183 · `*.united.com` · P3 · unresolved**

A gate-agent tool issues a valid JWT to anyone who posts a station code and a gate number. No credential, no employee verification, no rate limit. The token then reaches a search action that queries the production reservation database by last name, destination and date of birth, returning full passenger PII: name, personal email and phone, loyalty number, booking reference, itinerary, seat, gate, boarding time.

**The measurement is the report.** Roughly 2,000 requests across six hubs, 50 common surnames and 20 dates of birth, yielding 11 reservations and 19 individual passengers with 11 unique personal emails. A stated method and a counted result, not "an attacker could enumerate."

**Whenever a tool exists for staff but lives on the public internet, post nothing but context to its auth route.** A kiosk, a gate, a store number, a device serial — anything that identifies a *place* instead of a *person*.

---

## 2 · The identity-provider attribute the user can write

> **Shape.** The access token carries a scope permitting self-administration against the identity provider's own API. If a tenancy-bearing custom attribute was never marked admin-write-only, the user rewrites it, re-authenticates, and the new claim is in the token the backend trusts.

**44c61de21b4e · `haiku-qa` · P3 · unresolved**

Three custom attributes carry the organization id, the domain used for tenant isolation, and an enterprise-feature flag. All three writable by the user through the provider API. Overwrite, re-authenticate, and the forged claims grant access to the target organization's data.

**The discovery path is worth memorising, because none of it required guessing:**

- the pool region and id come from the token's own issuer claim
- the app client id comes from the token's own client claim
- the scope granting self-administration is visible in the token's scope claim
- a source map published alongside the app recovered the full client source, including the authentication flow and every endpoint

Then one call to the provider's get-user operation lists the custom attributes, and one write test per attribute establishes which are self-writable.

**Decode every token you hold before doing anything else.** In this corpus a token has given up the pool, the client, the scopes and the tenancy model without a single request to the target.

---

## 3 · The unauthenticated oracle that walks out the reset token

> **Shape.** A known CMS or framework version with a query-sanitization bypass. An undocumented parameter reaches the query builder untouched, and a count field in the response becomes a one-bit oracle. Character by character, that oracle reads private columns — including the ones the password-reset flow depends on.

**17a715008c76 · `infiniteathlete.ai` · P1**

An undocumented `where` key passes both validation and sanitization and reaches the database layer verbatim. It supports relation traversal, so a join through the ownership foreign keys present on every content type reaches the admin users table and filters on private fields. The pagination total flips with each guess.

Extracted: the administrator's email address, then — after triggering the product's own forgot-password flow — the 40-character reset token, one character at a time.

**The chain is complete and the last step was deliberately not taken.** The report says so plainly: *"The reset token was not used to complete the takeover."* Everything up to the takeover is demonstrated; the takeover itself is stated as the consequence.

**Fingerprint the framework version first.** This is the one play in the class where reading a version banner and matching it to a known sanitization bypass is the whole discovery.

---

## 4 · Default credentials on an ops panel

**3701766 · `staging.uipath.com` · Critical · triaged**

A monitoring instance deployed with `admin`/`admin`. Full admin session: 649 dashboards covering production and staging, 31 datasources reachable through the proxy endpoint, six staff email addresses with admin roles.

**Why it landed at Critical despite being the least sophisticated finding in the corpus:** the report enumerates what the session *reaches* rather than stopping at the login. Datasource proxying to internal backends, the ability to create alerting channels that egress data, the ability to add admin users — and the observation that the default password can be silently changed, locking legitimate admins out of their own monitoring.

**The login is not the finding. What the session touches is.**

---

## 5 · OTP with no attempt limit

**3714964 · `www.vodacom.co.tz` · Critical claimed → informative**

A six-digit code, unauthenticated request, no rate limit, no lockout, no attempt threshold, and the code stays valid at least 30 minutes — confirmed because the server keeps answering *wrong OTP* rather than *expired*.

**It came back informative.** The arithmetic is unarguable and the takeover was not demonstrated end to end against a victim account — correctly, since that would need someone else's phone. This is the structural bind of OTP findings: the honest proof stops one step short, and the missing step is the one that pays.

**What to do instead.** Run the brute force against **your own** number and complete the takeover on your own account, then state the victim case by inference. Demonstrating that 10,000 guesses in N seconds succeeded on an account you control is a demonstration; describing that it would succeed on a stranger's is not.

Note also that the "no rate limit" framing is discarded on its own in most programs. What makes this reportable at all is the OTP validity window plus the missing lockout — two failures, not one.

---

## 6 · Cryptographic signature counting

**3810939 · `github.com` (a protocol codebase) · Medium · not-applicable**

A consensus validator counts raw signature byte-strings against an agreement threshold instead of counting distinct recovered signer addresses. Because two encodings of the same signature recover the same address, duplicating each signature halves the effective Byzantine threshold — 10 genuine signers pass a check that should require 19. No privileged key needed; the signatures are ordinary broadcast traffic. The forged proof is stored and re-served to peers with no re-validation, so it propagates.

**Not applicable.** Deep, correct, and outside what that program pays for. The finding is real; the venue was wrong.

**The reusable idea is the class, not the protocol:** wherever a threshold is met by *counting* things, check whether the count deduplicates on identity or on encoding. The same defect shape appears in multisig, in quorum checks, in vote tallies and in any "N distinct approvers" gate. The report notes that the same codebase already fixed this exact class in a different code path and never updated this one — an enforcing sibling, in a cryptographic setting.

---

## What the outcomes teach

**Two of six did not convert, and neither failed on the technique.**

- The OTP report failed on **proof shape**: the arithmetic was right and the takeover was not shown on a real account.
- The signature report failed on **venue**: correct, deep, and not a class that program buys.

Both are avoidable before the turn is spent. Check the program's excluded classes at DISPATCH, and plan the proof so its last step lands on an account you control.

**The two P3 results share a property: both are unauthenticated paths into production data, and both are on staging-adjacent or internal-facing hosts.** Worth knowing that the class discount for a non-production hostname applies even when the *data* behind it is production — the gate-agent tool queried the real reservation system and still sat at P3.

**Decode the token first.** Two of these six turned on information the token itself carried: the identity-provider pool and client, and the self-administration scope. It costs one command and no requests to the target.

**Enumerate what the session reaches.** The default-credentials report is the least technical finding in the corpus and scored Critical because it counted dashboards, datasources, staff accounts and the specific admin operations available. The bypass is the beginning of the report, not the end of it.
