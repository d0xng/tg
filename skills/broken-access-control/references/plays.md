# The ten plays

Each play: the **shape** that transfers to any target, then the corpus case that proves it converts, named and with its outcome. Refs point at `~/Desktop/skills/personal-corpus/`.

Outcomes are stated honestly, including the ones that came back `informative` — a play that converted once and failed once teaches more than one that only ever worked.

---

## 1 · The enforcing sibling

**Shape.** An endpoint answers you. Its neighbour — same service, same resource, same plane — refuses you. The correct control already exists in that codebase and was not applied here.

Five cases, and the play is both how they were *found* and why they were *believed*.

**3909250 · abercrombie.com · High · duplicate**
Two BFF config resolvers, `switches` and `FCQ`, accept a caller-supplied configuration name and return whatever it holds, unauthenticated and with no allowlist. Between them: payment-gateway account and password, the full Braintree public+private key pair, A&F's own refund encryption key and salt, both reCAPTCHA server secrets, a gift-card integration secret, internal hostnames, a production CS platform api key, an employee's corporate email.
A third resolver in the same schema, `config`, takes the same kind of caller-supplied name and **refuses every one of them**. The report says it plainly: *"That contrast is the clearest statement of the defect."*

**3896657 · abercrombie.com · Medium · new**
`updateGiftBox` does not verify that the supplied `orderItemId` belongs to the caller's cart. Two sibling mutations on the same endpoint, `removeBagItem` and `moveToSavedForLater`, resolve the identifier inside the caller's own order and reject foreign ones. *"This shows that cart lines are not intended to be globally addressable and that an appropriate ownership check already exists within this service."*

**3890078 · new.express.adobe.com · Medium · new**
On the **identical** `restricted/{urn}` path: `manifest` and `primary` return `403 user does not have access to premium content`; `component` and `rendition` return `200` with no `Authorization` and no api-key header at all. The service classifies the asset as premium-gated and then serves its constituent bytes unauthenticated.

**3753228 · firefly 3P gateway · Critical claimed → informative**
The Image endpoint correctly returns `403`; the LLM and Video endpoints on the same gateway check nothing. *"…proving the capability exists but was inconsistently applied."* See play 6 for why this one still came back informative.

**3749634 · firefly.adobe.com · Medium · resolved**
`firefly-3p.ff.adobe.io/v2/3p-images/generate-async` enforces the entitlement and returns `403 user_not_entitled`; `run-workflow.adobe.io/action/execute`, a sibling on the same platform, does not. *"This proves the enforcement primitive exists in Adobe's stack and was not applied uniformly."*

> **How to run it.** Before enumerating ids, enumerate siblings: every verb, every operation in the schema, every adjacent path segment, every version, every sibling service on the plane. A non-uniform column is the finding.

---

## 2 · The decorative credential

**Shape.** A header is required to be *present* and never validated. Any value passes. The endpoint looks authenticated and is not.

**3842276 · firefly.adobe.com · Medium · duplicate**
The job runner rejects a missing bearer (`403`) and an invalid signature (`401`), and requires an api-key header to be present — but does not validate its value: `completely-fake-not-a-real-client` is accepted identically to the real client id. Two consequences: no access control, and **broken attribution** — abuse cannot be traced to a client identifier because any string is accepted.

**3895309 · new.express.adobe.com · Medium · new**
`POST /dev/presign` returns a signed one-hour S3 PUT URL to a **garbage bearer**. The report states the logic exactly: *"a route with an authorizer rejects an invalid token. This is the control that proves none exists."*

**3749634 · Medium · resolved** — shape-not-value: the gateway required `x-gw-ims-org-id` to look like `<uuid>@AdobeOrg` and never checked the value against the bearer's real org or any registry. Thirty-two zeros worked.

> **How to run it.** Control 2 and control 3 in `controls.md`. Always distinguish *malformed* from *well-formed but unregistered* — they are different findings.

---

## 3 · The client-supplied identity header

**Shape.** A header names the account, and the server believes it.

**3914032 · *.newegg.com · Critical · new**
`/ailab` determines the calling customer solely from `x-customer-number`, a plain 9-digit number. No cookie, no bearer, no session required or checked. Reads another customer's full conversation transcripts and a 30-day behavioural profile; writes turns into their conversation and overwrites the cached greeting on their welcome screen.

The clause that made it Critical rather than dismissible: **the header takes precedence over a live authenticated session belonging to a different customer** — *"so the issue is not a fallback path for anonymous callers."*

The number is not secret: it sits in the `CustomerLogin` cookie as `LoginId`. A parallel header addressed a second namespace covering visitors who never signed in.

**3849806 · milanuncios · Medium · pending** — `X-MA-User-Id` alongside a `userId` in the path, on endpoints enforcing nothing on any verb.

> **How to run it.** Test the header **while authenticated as a different identity**, not only while anonymous. Precedence over a live session is the difference between High and Critical.

---

## 4 · Unauthenticated CRUD on a backend found in the bundle

**Shape.** A config key in the JavaScript names a backend the UI talks to directly. The backend authenticates nothing.

**3776894 / 3777402 · Adobe Express · Critical → duplicate, then informative on resubmission**
`inpaintingResultsApiBaseUrl` in a production bundle points at an API Gateway proxying DynamoDB `PutItem`, `UpdateItem`, `DeleteItem` with **no** bearer, api-key, cookie or WAF. The same `/dev` stage URL is used for local, stage and production.

**The read side-channel is the part worth memorising:** the proxy looks write-only, but `UpdateItem` and `DeleteItem` accept `ReturnValues`. `ALL_NEW` and `ALL_OLD` return the item's complete attributes. A write API becomes exfiltration.

Verbose errors additionally disclosed table names, key schemas and attribute types.

**3791373 · new.express.adobe.com · High · duplicate** — a `playground/html` web action with full CRUD keyed by a caller-supplied session id, no credential on any verb.

**3895348 · tidyup-dev · High · new** — the one service on its inference plane *not* behind the api-key gateway. `POST /v2/storage/block/init` returns a presigned S3 multipart URL to an anonymous caller; content type is not validated against the bytes.

> **How to run it.** When `js-miner` surfaces a hardcoded backend base URL — especially one whose value is identical across environments — this is the play. Test every verb unauthenticated, then look for a return-values parameter.

---

## 5 · Object reference with no owner check

**Shape.** The plain BOLA. The id is in the path, query, body or a header, and possession of it is treated as authorization.

| ref | host | the object | outcome |
|---|---|---|---|
| 3861742 | mercadopago.com.mx | seller's item id → private cost basis, exact inventory, SKU/GTIN | Medium · triaged |
| 3895140 | wolt.com | `userId` path param → another user's KYC onboarding record; **get-or-create writes under the victim** | Medium · new |
| 3851962 | coches.net | `reservationId` → buyer's name, phone, email; sibling endpoint returns a live Stripe session secret | High · new |
| 3866958 | mercadopago.com.ar | subscription flow id, **unauthenticated** → name, email, payer id, card metadata | Medium · duplicate |
| 3842276 | firefly.adobe.com | job id → result + presigned S3 URL; also cancels the victim's job | Medium · duplicate |
| 3898191 | firefly.adobe.com | storage object id → victim's private upload recovered through an AI transform that preserves source pixels | Medium · duplicate |
| 3895191 | new.express.adobe.com | event id → rewrite or soft-delete another user's event; RSVP roster with emails | High · duplicate |
| 3895298 | abercrombie.com | sequential `orderId` → unauthenticated payment reauthorization | High · pending |

Two things separate the Highs from the Mediums here, and neither is the bug:

- **Enumerability.** A random UUID bounds it to per-record; a sequential counter means the whole population.
- **Whether a write was demonstrated.** Read-only cross-account is Medium territory; a persisted write the victim can see back is High.

The Firefly job-id case adds a multiplier worth knowing: the response carried a **presigned S3 URL**, anonymously fetchable for an hour. After the cross-tenant read, no credential is needed at all — the URL is a self-contained exfiltration token.

---

## 6 · Entitlement never checked

**Shape.** The token is valid. It was never asked whether it was *paid*. The tell is that the UI enforces the limit and the API does not.

**3753228 · firefly video model · Critical claimed → informative**
A free account with 10 credits invoked Claude Sonnet 4.5/4.6, Gemini 2.5/3.0/3.1, Veo 3.1 and Sora 2 through the 3P gateway. Four videos generated and downloaded, ~1,320 credits' worth, **zero consumed**. The same account was blocked by the UI at 5 image and 3 video generations.

**3749634 · run-workflow · Medium · resolved**
An enterprise product documented at ~USD 1,000/month, gated on OAuth server-to-server credentials and an admin role. The deployed gateway checked only that the bearer carried a scope Adobe issues to *every* consumer account, plus that an org header was shaped correctly.

**Why the Critical became informative.** Both are real, but the impact is metering and cost, not an authorization boundary between users. Rated as entitlement stories they are worth less than they look. **Lead with the cost to the vendor and route the class to `resource-abuse`;** do not frame it as access control and claim Critical.

---

## 7 · The allowlist regex that is not anchored

**Shape.** A host allowlist implemented as a regex with a lookahead containing `.*`, evaluated against the whole URL. It asserts the needle appears *somewhere*, never that it is the authority.

**3909155 · new.express.adobe.com · High · triaged**
**3909271 · firefly.adobe.com · High · new**

One defect, two products, two reports. The table decides both *whether* a URL may be fetched and *whether the user's credentials are attached*:

```
^(https:\/\/)(?=.*\.adobe\.io\/).*$

https://attacker.tld/collect?pin=.adobe.io/   → passes, token attached
https://adobe.io.attacker.tld/x               → correctly refused
http://attacker.tld/c?pin=.adobe.io/          → correctly refused
```

The table is a *real* gate that genuinely refuses attacker hosts. It is defeated by one specific defect in how each row is anchored — which is exactly why the report is convincing rather than dismissible.

Resource URLs persist inside the shared document with no normalisation, so a shared document keeps working against every recipient. The victim self-selects by opening it. Token: 24 hours, 40 scopes, demonstrated reading *and writing* the victim's profile.

> **Reproduction trap, stated in both reports.** The credentialed `GET` is preceded by a CORS preflight carrying `Access-Control-Request-Headers: authorization,x-api-key`. **The collector must answer `OPTIONS` with `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Headers: *`** or the browser never sends the credentialed request — an outcome indistinguishable from the vulnerability not existing. Put this at the top of the reproduction steps.

**Same technique, new host, is a new finding.** That is how one regex defect became two Highs.

> **This play is one door into a larger room.** The payoff — a signed-in visitor's
> SSO token taken from an origin the identity provider trusts — is reached just as
> often by a parameter landing in the authority position of an imported module, or
> by a reflected value inside an inline `<script>` literal. All three, the two
> enablers that decide whether they convert (no enforcing CSP; the origin
> allowlisted for credentialed cross-origin reads), and the five corpus cases are
> in `../../xss/references/escalation.md` §3b. Recognition of the module
> variant belongs to `../../js-source-to-sink/references/code-sinks.md` §1b.

---

## 8 · Origin reachable behind the edge

**Shape.** The WAF is not a control on the origin. Find the origin address, address it directly.

**fde0827c1181 · saudiare.sa · P1 · triaged**

```
dig TXT  →  SPF record discloses origin IP  →  curl --resolve past Cloudflare
         →  api key hardcoded in the public JS bundle
         →  guest-token endpoint requiring no credentials
         →  /api/admin/* accepts any valid token regardless of role
```

Result: PII of employees and 959+ citizens and companies, 45 internal procurement tenders with financial data, 353 internal file uploads, the complete CMS.

Four independent weaknesses chained, none of which is a finding alone. **The role check was the actual defect** — the rest is reachability.

---

## 9 · Gated on state instead of identity

**Shape.** A write endpoint refuses you with a *business-state* error rather than `401`/`403`. It never checked who you are; it checked whether the object is in an editable state.

**3849699 · milanuncios · Critical claimed → informative**
`GET /v1/self-service-flow/{email}` returns, unauthenticated, a seller's full name, phone, Spanish tax id (NIF/CIF), company name and postal address. The `PUT` siblings returned `422 WRONG_FLOW_STATUS` — *"rather than 401/403 when called unauthenticated, confirming they perform no identity or ownership check and gate only on flow state."*

**Why it came back informative despite that reasoning being correct:** the report also says *"This was not exercised against third-party data."* The read was proven; the write was inferred. Honest, correct not to attempt it — and it capped the outcome.

> **What to do instead.** Demonstrate the write against **your own** object in an editable state, and show the state error is the *only* gate. That converts an inference into a demonstration without touching a third party.

---

## 10 · The server-side relay that substitutes a secret

**Shape.** A service fetches a caller-named URL and, before sending, substitutes a stored credential into the request.

**3909187 · new.express.adobe.com · High · new**
`POST /v1/forward` takes a caller-controlled manifest: endpoint, method, headers, query, path params and body. Before fetching, it replaces the literal `"$secureApiKey"` in the caller's body with the OAuth client secret stored for the add-on named in a **body field** — not derived from the caller's identity.

Two independent paths to the same credential, failing differently:

1. **Exfiltration** — the destination is caller-chosen, so the secret is addressed to any host the attacker names.
2. **Relay** — point `endpoint` at the provider's *genuine* token URL and request a `client_credentials` grant: the upstream body is relayed back, and it is a live app-authentication token. **This path survives an allowlist on the destination.**

The report's "Not claimed" section is the model to copy: it lists every internal-network form tried against the guard — decimal, octal, DNS rebinding, link-local, the internal hostname resolving to RFC1918 — and that each was correctly refused. Ruling out the SSRF is what made the credential finding credible.

---

## The two frames that lose value

Both are real findings filed under the wrong class:

1. **Metering framed as authorization** (play 6) → lead with cost, route to `resource-abuse`.
2. **A write inferred rather than demonstrated** (play 9) → demonstrate on your own object.
