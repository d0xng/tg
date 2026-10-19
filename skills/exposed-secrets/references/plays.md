# The plays — exposed secrets and information disclosure

Built from 22 of d0x's own reports across `hardcoded-creds`, `info-disclosure` and `unprotected-creds`. Each play: the **shape** that transfers to any target, then the corpus case and its outcome.

The distribution to absorb first: **4 Critical, 2 High, 11 Medium**, and **8 duplicates plus 5 informative** — the highest duplicate rate of any class in the corpus. Leaked keys are what everyone finds. What separates a Critical from an informative here is never the discovery; it is which API the key opens and whether it was actually called.

Refs point at `~/Desktop/skills/personal-corpus/`.

---

## 1 · The marketing-platform key that holds the whole customer record

> **Shape.** A customer-engagement, marketing-automation or CRM platform key. Its API is designed for bulk export by identifier, and the profile it exports is everything the product ever synced about a user.

**3763293 · `com.public.app.development` · Critical · resolved** — the model report of this class.

The chain: a key in a publicly readable environment file on the company's WordPress infrastructure → the vendor's export-by-identifier endpoint → **one email address returns the complete profile.**

What came back, from a broker-dealer: legal name, date of birth, home address, phone, brokerage account number, SSN validation status, income and net-worth brackets, full portfolio holdings with exact amounts, deposit and dividend history, device fingerprints. The same key also carried **write** and **delete** on those profiles.

Three things that made it Critical rather than a key report:

- **It was called.** Validated against four distinct users, one of them a real consumer found through a public search — not four of the reporter's own accounts.
- **It was matched to the in-scope asset.** The report proves the key's workspace is the one the in-scope mobile app sends data to, by quoting the endpoint hardcoded in the app's own resources. That is what makes a third-party vendor key an in-scope finding.
- **It quoted the program's own words.** The disclosed fields are lined up against the policy's definition of sensitive data.

**Where these keys live:** `.env`, `.env.local` and config files on adjacent infrastructure — a marketing WordPress, a status page, a preview deployment — far more often than in the main app bundle.

---

## 2 · Cloud tenant credentials

> **Shape.** An identity-provider client id and secret plus the tenant name. Three values, one token endpoint, and the token is good for every service the app registration was granted.

**3583718 · `*.costco.com` · Critical · duplicate**

Client credentials for a cloud tenant, publicly accessible, minting valid tokens. Reach: 20+ platform services — management API, DevOps, key vault, storage, document and relational databases, BI, notebooks — plus 925 role definitions, real subscription ids, management-group and resource-group names including production, and container-registry names.

And the payable part: the token carried a role on a **member-lookup API that queries member data by card number**.

**The escalation order that report follows is the one to copy:** mint the token first (proves the credential is live), enumerate what it can reach second (proves the blast radius), then find the one endpoint that returns customer data (proves the impact). Stopping after step one is a key report.

---

## 3 · The serialized error object — two reports, and the most distinctive play here

> **Shape.** A server-side rendered page or API catches an HTTP-client error and serializes the **whole error object** into the response. That object carries the client's configuration, and the configuration carries credentials — or, worse, the process's shared connection state.

**9e1112b24414 · `*.quidco.com` · P1 · triaged**

An unauthenticated `GET` with a trivial parameter returns the full HTTP-client error config, including an `auth` block with a server-side username and password. Chained to registering on the admin dashboard and exporting **4,043 real loan records** covering 311 applications, amounts from £500 to £35,000, across 13 lenders.

**3861921 · `*.mercadopago.com.mx` · Medium · triaged** — the same shape, one level deeper and genuinely unusual.

Requesting a nonexistent object returns the serialized error, whose config contains the **process-wide Node HTTP agent**. When another user's request is in flight on that process, the agent's state holds `parser.outgoing._header` — the complete raw internal request of an unrelated user, including every authorization header.

Two details make it land:

- **An all-zero UUID works.** No victim identifier is needed. The report says why that matters: it proves the object identifier is not the security boundary, and that normal backend concurrency is the source of the credentials.
- **Repetition harvests.** Across a controlled run, at least eight distinct third-party identities appeared, in routes for identity verification, asset management, privacy preferences, segmentation, annual financial returns and trusted-network context.

The report also pre-empts the obvious closure: *"This is not a stack-trace-only report. The stack trace is incidental."*

**How to find it:** send a well-formed but nonexistent identifier to every endpoint that fetches something server-side, and read the error body in full. Look for `config`, `auth`, `httpAgent`, `_header`, `sockets`.

---

## 4 · The unauthenticated datastore behind a CMS

> **Shape.** A content platform exposes its search backend without authentication. The index holds not just content but **file assets**, and someone stored a configuration file as content.

**9a1beb3359b6 · `*.united.com` · P2 · unresolved**

Fingerprint header identifies the platform → its search endpoint answers unauthenticated → 9,294 records → a YAML configuration file stored as a CMS asset, holding **20+ production credentials in plaintext**: OAuth client secrets, api keys, basic-auth passwords → one pair mints a token with 30 scopes against a telecom subscriber API → subscriber lookup by phone number, geolocation, data usage, dealer, billing.

The same report also reached unauthenticated CRUD on cloud datastore proxies — read, write and delete confirmed against production tables.

**The lesson is the pivot, not the exposure.** An unauthenticated search index is a Medium. Searching it for `password`, `secret`, `client_secret`, `.yml`, `.json`, `postman` — and then *using* what you find — is what produced the P2.

---

## 5 · Capability tokens preserved by public archives

> **Shape.** The product puts a bearer-style capability in a URL. Public web archives have been indexing those URLs for years, and their APIs are queryable without authentication.

**3899152 · `*.trip.com` · Critical · duplicate**

Payment tokens in cashier URLs. A live recount through the archive's own query API found 304 archived URLs carrying a token across three hosts, deduplicating to **236 distinct values**. Possession alone authorizes the order lookup with no session, which returns a cart identifier that in turn authorizes reading passenger and contact details and **persistently modifying them**.

**The handling is the model.** Write capability was demonstrated only against the reporter's own bookings, reverted and verified. Archived third-party tokens were **counted, never replayed**. The number is the impact; using the tokens would have added nothing but harm.

**Run this on any product that puts a token in a URL** — password reset, invite, share, payment, unsubscribe, document preview. The archive query is unauthenticated and takes one request.

---

## 6 · Third-party keys that are worth something — and the ones that are not

This is the judgment that separates the Mediums from the informatives, and the corpus has examples on both sides.

**Worth pursuing:**

| ref | key | why it converted |
|---|---|---|
| 3632004 | a link-shortener live key | mints unlimited links **on the brand's own official short domain**, with no destination validation. Those links pass corporate mail filters and URL reputation tools precisely because the domain is trusted. Medium · duplicate |
| 3907161 | a survey-platform OAuth token, published | lists surveys, reads, creates and **deletes** customer-research responses, anonymously. Critical · triaged |
| 3438542 / 3663259 | content-delivery and **preview** tokens | the preview token reaches **unpublished drafts** — content the product deliberately has not released. Medium / informative |

**Not worth much on its own:**

**3444834 · an analytics ingest key · Medium · duplicate.** Injecting events inflates the vendor bill and pollutes dashboards. Real, and it is a cost-and-integrity story with no data behind it. The report is honest about that, and it still came back duplicate.

> **The dividing question is not "is the key secret."** It is: **does it read data, mint compute, or write to something someone trusts?** A key that only writes into an analytics funnel fails that test. A key that mints links under the brand's own domain passes it, because the trust in the domain is the asset.

---

## 7 · The application serializing its own internals into the page

**3857852 · `*.mercadopago.com.ar` · Medium · duplicate**

A server-rendered assistant page embeds its full agent-orchestration configuration in the HTML delivered to **unauthenticated** visitors: 68 internal service endpoints with their stated purposes, the per-server tool catalog, and the configuration flags. Five of those services are marked as allowing unauthenticated access with no tool filter and no role filter — three of them exist to *discover and execute internal APIs*.

**Read the server-rendered HTML, not only the bundles.** Configuration objects inlined in a `<script>` block are invisible to bundle mining, and this is the second corpus report to turn on that habit.

---

## 8 · Disclosure without a secret at all

Two reports in this class involve no credential, and one is High.

**3856000 · `www.milanuncios.com` · High · triaged — statistical de-anonymization.**

The platform hides a seller's exact location behind per-request random jitter within roughly 100 m. Because the noise is zero-mean and **re-rolled on every request**, sampling the same public endpoint a few dozen times and averaging recovers the true coordinates to building level. The same response carries the seller's full name, and the ad ids are sequential.

**The control itself is the vulnerability.** Per-request jitter is the platform's defence against exact-location disclosure, and averaging defeats it. Whenever a value is obfuscated *per request* rather than *per object*, sample it and average.

**3676048 · a public-page API · Medium · duplicate** — two unauthenticated requests turn any public page into the personal email addresses of everyone who edited it, at the scale of every public page the search engines have indexed.

**3513669 · `*.capitalone.com` · High · informative** — complete payment-transaction details, including recipient identity and partial account numbers, in `GET` query parameters, mirrored into the tag-management system's own URLs. Four confirmed real customers, over $10,900 in transactions. Informative despite being real and being High — worth knowing before spending a turn on parameter-logging findings.

---

## What did not convert, and why

**8 duplicates — the highest rate of any class.** Leaked keys are the first thing every hunter greps for. **Check the ledger and the corpus before spending a turn**, and prefer the key that needs a chain: the analytics key is found by everyone, the config file inside an unauthenticated search index is not.

**5 informative.** The pattern across them:

- **Read-only access to non-sensitive content.** Two CMS-token reports on one host: 221 entries, 11 unpublished drafts. Real access, ordinary content.
- **Reconnaissance value only.** Enumerating an admin permission model and audit-event types tells an attacker what is monitored. That is intelligence, not impact.
- **PII in a URL parameter**, even with confirmed real customers and dollar amounts.

**1 not-applicable — `4a80967c30ad`.** A document marked internal-government-use-only, publicly downloadable, containing 272 provider identifiers. The finding was *"a file is public"* — no authorization was bypassed, nothing was enumerated, no control failed. **A sensitive document at a public URL is a data-handling complaint, not a vulnerability**, unless you can show how the URL is discoverable at scale or that an access control was meant to be there.

The `815763ba0075` FOIA-redaction report resolved at P3 for a comparable finding — inconsistent redaction across an archive — because it demonstrated the *inconsistency*: the same archive redacts signatures in most documents and not in two. **The comparison is what made it a defect rather than an observation.**

---

## The discipline that made the Criticals land

**Call the API.** Every Critical in this class has request-and-response evidence against the vendor endpoint. Every informative stops at reachability or at content of no consequence.

**Prove the key belongs to the in-scope asset.** The Braze report quotes the endpoint hardcoded in the in-scope app's own resources to tie a third-party workspace to the program. Without that step, a vendor key is out of scope by default.

**Count what is reachable.** 4,043 loan records. 236 distinct archived tokens. 9,294 indexed records. 8 distinct third-party identities. 272 provider identifiers. The count is what moves a leak from Medium to Critical, and every one of these is a number a triager can verify.

**Say what you did not do.** Archived tokens counted, never replayed. Writes only against owned bookings, reverted and verified. That restraint is what lets the number stand unchallenged.

**Rotation.** Every one of these reports names a live credential. Lead the report with where it is exposed and whether it has been rotated — the program's first action is rotation, and telling them that first is what a good report does.
