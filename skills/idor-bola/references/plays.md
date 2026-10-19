# The plays — IDOR / BOLA

Built from 18 of d0x's own reports on this class. Each play: the **shape** that transfers to any target, then the corpus case that proves it converts, with its outcome.

Outcomes are stated honestly, including the three that resolved Low and the two Bugcrowd `not_applicable`. A play that converted four times and failed twice teaches more than one that only ever worked.

Refs point at `~/Desktop/skills/personal-corpus/`.

---

## 1 · The vendor preference API — the highest-converting play in the corpus

**Four reports, four different hosts, three of them Critical or High.** This is the play that converts repeatedly, and it is the clearest example of *same technique, new host, new finding*.

> **Shape.** A marketing, email-preference or unsubscribe page renders a per-tenant credential pair **into the page source**, and the vendor API those credentials address performs **no authorization at all** — it answers for any subscriber identifier you supply.

The credential is not a secret in the program's mind: it is a widget configuration. The finding is that the API behind it has no authorization, so the "configuration" is a master key to the subscriber base.

**How to run it**

1. Find the preference, unsubscribe or email-settings page. `curl -s` the **raw HTML** — these values sit inline in a `<script>` block, which bundle-mining misses entirely.
2. Extract the pair. It is usually a long hex account identifier plus a small integer tenant/integration id.
3. Call the vendor endpoint with a victim identifier and no credential of your own.
4. **Then look for the second lookup parameter.** This is the escalation and it is what turns High into Critical.

**The escalation, in the corpus**

| ref | host | lookup | outcome |
|---|---|---|---|
| 3481692 | `*.theory.com` | `&email=<victim>` | **Critical** · triaged |
| 3819989 | `*.theory.com` | `&uid=cdp-<N>` — **sequential** | **Critical** · retesting |
| 3487578 | `*.epicgames.com` | `&email=<victim>` | **High** · resolved |
| 75e46a2608ab | `*.assurancewireless.com` | `&email=<victim>` | P3 · unresolved |

The two Theory reports are the lesson. The first needs a victim's email — per-record disclosure, bounded. The second found that the same API accepts a **sequential integer** identifier, which converts a per-email lookup into a walk of the entire subscriber base with no victim knowledge at all. The report says it plainly: *"It is a bypass of the resolved case but with an additional ingredient, the iterable sequential UID."*

**So when this API answers: enumerate its parameters before writing it up.** An `email=` lookup is a finding; a sequential `uid=` on the same endpoint is a different and much larger one.

Per-record PII observed across the four: full name, personal and corporate email, phone with geolocation and timezone, **GPS coordinates**, device fingerprint, purchase history, subscription state, internal customer ids, minor-status classification.

---

## 2 · The RPC proxy that drops the session

> **Shape.** A generic server-side proxy takes a target service and method in its body and returns the routed service's raw response. It authenticates *the caller* but does not forward that session to the service it invokes, so the inner service falls back to an identity field in the body.

**3897811 · `*.trip.com` · Critical · new**

`soaRouteService` names a `serviceCode` and `method` in the body and returns `responseJsonBody` verbatim. The invoice service, which on its normal path derives the account from the session, falls back to a body `uid` when reached through the proxy.

Two things make this the strongest report in the class:

- **The enforcing sibling is the same service.** Reached directly, it ignores the body `uid` and uses the session correctly. One path enforces object-level authorization and the other does not — that contrast is the whole argument.
- **The write half.** The mutate method takes its subject from the same body field, so an attacker does not only read another account's billing record, they overwrite it — invoice title, taxpayer number, company address, bank details. Demonstrated between two controlled accounts and reverted.

And the identifier supply was measured, not assumed: an anonymous page returns 30 real user ids per load, 119 distinct ids harvested from 16 loads with no saturation.

> **The restraint is worth copying.** No harvested third-party identifier was ever submitted to the billing endpoint. The report states why: a nonexistent id returns a response byte-identical to a real account with no saved record, so the request *yields information only in the branch where it discloses a stranger's bank account*. It was not sent, and the program was told it can settle that hop internally with one query.

**Look for a proxy whenever one host answers for many services.** A single endpoint whose body names the downstream is a place where session context gets lost.

---

## 3 · Path authorizes one segment, fetches by another

> **Shape.** A nested route checks the *first* identifier against the caller and then resolves the *second* globally. The check is real, which is why it survives review — it is simply checking the wrong segment.

**3851866 · `www.coches.net` · Medium · triaged**

`GET /publisher/users/{userId}/drafts/{draftId}` requires `{userId}` to equal the caller's own id, then fetches the draft by `{draftId}` with no ownership check. Put **your own** id in the path with **any victim's** draft id and the draft comes back: seller email, phone, vehicle plate, postal location.

`draftId` is a single global counter incrementing by one across all users, so the whole corpus is walkable in creation order.

**Test every segment of a nested path independently.** A route that rejects a foreign id in position one may not check position two, and the presence of a working check in the URL is what makes reviewers stop looking.

The report also states the write side honestly: publish, update and delete on the same draft **do** enforce ownership and return `403`, so the finding covers confidentiality only. Saying that is what keeps the rest credible.

---

## 4 · Body identity field not bound to the token

> **Shape.** The endpoint requires an identity field in the body — it `400`s when the field is empty — and never compares it to the token's subject.

Three reports, and the outcome split is the lesson:

| ref | surface | direction | outcome |
|---|---|---|---|
| 3793330 | per-user attribute store, `POST` with `userID` in body | **read** | **Medium** · duplicate |
| 3744810 | assistant feedback, `userGUID` in body | write-only | **Low** · resolved |
| 3755067 | assistant feedback, `user_id` in body | write-only | **Low** · resolved |

**Write-only body-field spoof caps at Low or Medium.** Both feedback endpoints were confirmed spoofable — a free account submitting events attributed to any other user, with unschemaed extra fields accepted — but `GET` returns `405`, so nothing can be read back. The impact is attribution poisoning and, where the data feeds a model, training-data poisoning. Real, and not High.

The read case scores higher because the response *is* the victim's record. In that report, omitting the optional field-selector returned the victim's entire stored record, so no field enumeration was needed, and the cross-user response was byte-identical to the victim's own read — matching ETag. **That byte-identity is the cleanest possible oracle**: it removes any argument that a default or placeholder object was returned.

**The controls that made these land:** empty field → `400 missing field` (the server reads the body id and never cross-checks the subject) · a well-formed nonexistent id → no not-found (no registry validation) · unschemaed extra fields accepted → the poisoning angle.

---

## 5 · Client-supplied impersonation headers

> **Shape.** A support or back-office feature ships an impersonation context as request headers. The backend routes on them without verifying the caller holds a role permitted to impersonate.

**3859466 · `*.mercadopago.com.mx` · High · duplicate**

Three headers — a seller id, an impersonation boolean, a site id — set by any ordinary authenticated session. The backend uses the seller id as the identity key and returns that seller's private financial dashboard.

**Seller ids are published in the platform's own listing and search responses**, so nothing has to be guessed. Confirmed read-only against four unrelated merchants: revenue, sale counts, payment-method mix, refunds and chargebacks, store topology, and **employee full names with internal user ids** — third-party personal data.

The scale argument is structural, not harvested: the response is driven entirely by an attacker-controlled header whose valid values are public.

---

## 6 · Org header treated as a routing hint

> **Shape.** A tenant header locates the object rather than authorizing access to it. The **list** endpoint is correctly scoped — a non-member gets an empty list — which is exactly why the per-object endpoints get missed.

**3749587 · `firefly.adobe.com` · Low · triaged** — batch status, stream and executions endpoints authenticate the caller and require the org header to match the batch's owning org, but never verify the caller belongs to that org. Read-only, and it returned presigned storage URLs that are then **anonymously fetchable**, so after the cross-tenant read no credential is needed at all.

**3807587 · `firefly.adobe.com` · High · triaged** — the write twin. A preset persists under the org named in the header, with no membership check. A free consumer account writes into any enterprise org's namespace, and setting the header to the vendor's own reserved namespace injects into the **globally curated catalog** served to every user.

**Two lessons.** The write twin scores far higher than the read — look for it. And *"the list endpoint is properly scoped"* is not a defence; it is the reason nobody checked the detail endpoints.

The same report also measured the identifier entropy rather than assuming it: the batch id is a template of user-chosen name, creation date, and only eight hex characters of randomness, so for an attacker who knows the first two the space is 2³².

---

## 7 · Unauthenticated write on a sequential id

> **Shape.** A REST resource accepts `PUT` on an integer id with no authentication and no ownership check, replacing the whole record.

**83aafc730520 · `*.wien.gv.at` · P2 · unresolved**

Any integer from 1 to N is a valid target; the server applies the submitted body directly. The conversion is what makes it worth reading: the platform exports these records as **official government-branded PDFs**, so an overwritten record produces a document that displays real employee names and real government phone numbers while its hyperlink points wherever the attacker chose.

**When a record is rendered into a durable artifact, the write IDOR is worth more than the read.** Look for export, PDF, invoice or print views on any object you can write.

---

## 8 · Credentials plus a chain, on a mobile surface

**62e829849e92 · `saudia android app` · P3 · unresolved** — four weaknesses chained: identity-provider client credentials in publicly readable mobile remote config → `alg:none` accepted on the id token → a hardcoded HMAC key satisfying the request-integrity header → **no object-level authorization on any booking endpoint**. No account, no user interaction.

**3770014 · `app.loadninja.com` · High · pending** — a second gateway found in the production bundle accepts ordinary user tokens on routes meant for signed admin calls, and those routes perform zero ownership validation. Chained to: resolve any user's internal account id from their email, read their project data and its stored content, and **inject projects into their workspace**.

> The pattern both share: **the object-level gap is the last link, and it is the one that pays.** The credential and the token forgery are how you reach the endpoint; the missing ownership check is the finding.

---

## 9 · The staging instance with no authentication

**3617605 · `*.huffpost.com` · High · duplicate**

A QA instance of a content platform, publicly reachable, zero authentication. The entry point was a request for what should have been a static config file that **returned a full user profile object instead** — which revealed the `/{username}.json` pattern that became the IDOR.

Paired in the same report with a production API returning an internal author-email field never rendered in the UI. 28 staff profiles, 50+ personal addresses, including an investigative journalist's personal address — the report calls that out specifically, and naming *who* the exposed people are is part of why it landed.

**An unexpected response shape is a route discovery.** A config path returning a profile tells you the routing is name-based.

---

## 10 · The enabler: reaching the endpoint at all

Two corpus reports were only reachable after a preliminary bypass, neither of which is a finding on its own:

- **`X-Forwarded-For: 127.0.0.1`** turned a blanket `406 Not Acceptable` into `200` on a staging gateway (d27402e38e53).
- **Source maps** recovered the original TypeScript, which defined the role model and proved which operations were meant to be admin-only — turning "this endpoint accepts my call" into "this endpoint accepts my call *and the vendor's own code says it should not*" (27f3e6774897).

---

## What did not convert, and why

**Two Bugcrowd `not_applicable`:**

- **27f3e6774897 · P2** — a viewer-role user could change a team's name and public flag. Every *other* team-management operation correctly returned `403`, which is a textbook enforcing sibling, and the source map proved the intent. It still came back not-applicable: the *object* reached was a team's cosmetic settings, and no data crossed a boundary. **A perfect proof of a missing check is not a finding if what it unlocks is trivial.**
- **d27402e38e53 · P3** — full read, modify and cancel of any user's basket by UUID. On a `.stg.` host reached through a forwarded-header bypass. **A staging environment with synthetic data caps the impact** regardless of how complete the bypass is.

**Three `resolved` at Low** — all write-only body-field spoofs, covered in play 4.

Both failures share a shape: the *authorization defect* was proven cleanly and the *object* did not carry enough. Rank candidates by object sensitivity before spending the turn — the ranking in the skill's Algorithm step 2 exists for exactly this.

---

## The severity discipline that made the rest land

**State enumerability explicitly.** Sequential counter → the whole population; a published identifier → the whole population without guessing; a random UUID → one victim and only with the id. The Theory pair is the same endpoint at two different points on that scale, and the difference is High versus Critical.

**Say what you did not do.** The Trip.com report names the exact request it declined to send and why the answer would have been uninformative in the safe branch. The coches.net report states the write endpoints correctly enforce. The Firefly report states the UI filter currently hides the injected presets. Every one of those sentences protects the claim that surrounds it.

**Measure the supply.** "119 distinct identifiers from 16 anonymous page loads with no saturation" is a number a triager can check. "The ids are enumerable" is not.
