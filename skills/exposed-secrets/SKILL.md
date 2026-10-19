---
name: exposed-secrets
description: "Validate exposed keys, tokens, credentials, private keys, reset links, and configuration secrets by identifying the service and proving bounded read-only impact. Use when a recognizable secret appears in JavaScript, source maps, environment files, Git metadata, logs, errors, storage, backups, or responses. `js-source-to-sink` discovers client leaks; this skill determines whether the material is public, invalid, restricted, or security-sensitive."
---

# Exposed Secrets — turn a leaked key into proven impact

`js-source-to-sink` (and any recon) FINDS secrets; **this skill EXPLOITS them** —
d0x's highest-converting move. **Existence is never a finding; impact is.** The
reflex: the moment you have a secret, identify the service and CALL its API
read-only to prove what it unlocks. A key you don't test is a Critical you didn't
find.

This skill also owns the *surfaces* that leak secrets — exposed `.git`, debug
logs, env/config/backups, source maps, PII datasets, client/local storage — but
the doctrine is the same everywhere: when a **live service credential** surfaces
in any of them, do not stop at "it's exposed" and hand off. **Pivot to the
exploitation table below and prove impact.**

## Doctrine — climb the safe ladder to impact, do not stop at discovery

Read `../_shared/references/safe-ladder.md`. It is the operating law of this
skill. Discovery is rung 0. The finding is the *proven impact*, reached
read-only, own-context, minimal, UAT-if-RoE-requires:

- **Rung 1 — read-only first.** Mint the token / call the API, read back granted
  scopes and one **non-PII** object. "This secret is live and over-privileged" is
  already a reportable fact and usually enough.
- **Rung 2 — own/anon context.** Export *your own* test record, register the
  account *you* control, read the object *you* seeded.
- **Rung 3 — prove the scale, don't hoard it.** One or two records prove the class. Never dump
  the table to "show scale" — state scale by inference.
- **Rung 4 — UAT for risky proofs.** If RoE restricts cross-tenant/PII to
  UAT/OAT, do the full proof there; on prod stop at a non-PII read + inference.
- **Rung 5 — writes/other-user-on-prod → not attempted: ask d0x directly before executing.**

Never emit "could potentially" / "informational" / "prove exposure and hand off"
for a PURSUE key. Calling the API IS the deliverable.

## Method — every key gets tested, no exceptions

0. **Read the context where the key was discovered** — the surrounding config
   object, the variable name, nearby base-URL/endpoints, sibling keys, how it is
   used. Context reveals which service it is for, its scope, and frequently
   surfaces *related* secrets. A key that looks low-value is often Critical once
   context shows its purpose. Never grab a key in isolation.
1. **Identify by prefix/host** (any source — JS, `.env`, Postman, APK
   `strings.xml`, API response, public GitHub, `.git` history, debug log).
2. **Call the service REST API to prove impact** — pull data/PII, mint a token,
   reach infra. Read-only first (rung 1).
3. **Enumerate perms non-destructively**: send empty/invalid bodies and read the
   error. `Access Denied` = no perm; a *parameter-validation* error = perm
   granted (write/delete/export). Never mutate real data to test.
4. **Rank by impact**: PII export > credential→infra > CMS drafts > config leak >
   event injection > link forging. Lead the report with the highest.

## Prefix → service → top play (the converting ones — port verbatim)

| Found | Service | Play |
|---|---|---|
| UUID `BRAZE_REST_API_KEY*`, `*.braze.com`/`sdk.<cluster>.braze.com` | **Braze** | **full-PII export.** `POST https://rest.<cluster>.braze.com/users/export/ids` `Authorization: Bearer <key>` body `{"email_address":"<email>","fields_to_export":["email","first_name","last_name","phone","country","custom_attributes","external_id","devices"]}` → full PII + custom attrs (financial/identity custom-attributes = Critical). Perm-probe `/users/track` (write), `/users/delete`, `/users/export/segment`. Cluster from APK `com_braze_custom_endpoint` (`sdk.iad-06`→`rest.iad-06.braze.com`). |
| `AIza[0-9A-Za-z_-]{35}` | **Google** | run the decision tree → `references/saas-key-exploitation.md` (Google AIza tree): validate Gemini (`/v1beta/models?key=`), list owner files (data), generation abuse, 403→Referer/Corpora bypass. Maps/Geocode = skip (informational). |
| GUID `client_id`+`client_secret`+`*.onmicrosoft.com` | **Azure AD** | `POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token grant_type=client_credentials&scope=<api>/.default` → Bearer; decode `roles`/`aud`. Reaches Management/Vault/Storage/internal APIs. |
| SSR error echoing `auth.username/password`/backend `url`; Supabase `sb_publishable_*`+open `/auth/v1/signup` | **server creds / Supabase** | read creds from the error → register (Supabase signup → owner) → dashboard bulk export. Typically converts P1/Critical when the dashboard holds regulated records. |
| `x-dot-server`/unauth `/api/es/search` | **dotCMS/Elasticsearch** | query `password OR secret OR credential` → download asset → OAuth pivot. |
| `preferences.*`/`em.`/`emails.` host + `pushplanet`/`USER_GUID` | **Zeta/Boomtrain/PushPlanet** | GetSubscriber PII IDOR → `references/saas-key-exploitation.md` (Zeta). Recurs across email-marketing brands; retail/finance = Critical. |
| `*.exacttarget.com`, `view.e.*`, classic `qs=` hex | **Salesforce SFMC** | CBC padding-oracle → cross-tenant subscriber PII → `references/saas-key-exploitation.md` (SFMC). |
| Stripe `sk_live_` | **Stripe** | secret key = account control (charges/refunds/customer PII). Critical. (`pk_` = public, skip.) |
| AWS `AKIA`/`ASIA`, GitHub `ghp_`/`github_pat_`, GitLab `glpat-`, Slack `xox*`, SendGrid `SG.`, Shopify `shpat_`, Twilio `AC…`, OpenAI/Anthropic `sk-`, Databricks `dapi` | **source-control / messaging / infra** | one rung-1 read-only call proves the grant (`X-OAuth-Scopes` header, `/v3/scopes`, `auth.test`, `scim/v2/Me`) → `references/saas-key-exploitation.md` ("Source-control, messaging, and infra keys"). |

Full per-service payloads, oracles, CVEs, and Converts? verdicts live in
`references/saas-key-exploitation.md`. Open it the moment you match a row.

## Verdict tiers — resolve every key here before you spend a turn on it

Import `../_shared/references/public-by-default-keys.md`. It has three tiers now:

- **SKIP (silent)** — public by design, zero bounty value even when exercised: Google
  **Maps**/Geocode `AIza`, Sentry DSN, Datadog client token, Amplitude/Mixpanel/Segment
  **write** keys, reCAPTCHA site key, Stripe `pk_`, Mapbox/Algolia search token, PostHog
  `phc_`, GA `G-`/`UA-`, LaunchDarkly client-side id, Turnstile sitekey. Leave them
  silently — no note, no lead, no mention.
- **PURSUE-WEAK (chain-only)** — a real payload exists but it does not convert alone:
  Branch.io `key_live_`, Contentful Delivery `CONTENTFUL_TOKEN`, Unleash
  `*:production.<hex>`, Bugsnag, Amplitude event injection. **Test them, record the
  result in `notes/`, hold them until a chain attaches** — a Branch link on the brand's
  own domain plus a credential-theft chain, a Contentful *Preview* token exposing
  embargoed drafts, an Unleash flag carrying a live coupon. Never lead a report with one;
  never drop one silently either.
- **PURSUE** — reaches data / compute / PII / infra: Braze REST key, non-Maps `AIza`,
  Azure AD client creds, Supabase `sb_secret_`/`service_role`, Stripe `sk_live_`,
  dotCMS/server creds, AWS `AKIA`/`ASIA`, GitHub `ghp_`/`github_pat_`, GitLab `glpat-`,
  Slack `xox*`, SendGrid `SG.`, Shopify `shpat_`, Twilio, Databricks `dapi`,
  OpenAI/Anthropic `sk-`, a Segment **workspace/management** token.

Same `AIza` string is SKIP for Maps and PURSUE for Gemini — resolve by *reachable API*,
never by prefix. Same for Segment: `writeKey` = SKIP, workspace token = PURSUE.

## Read-On-Demand References

- `references/saas-key-exploitation.md` — **the primary key-exploitation
  reference.** Full per-service payloads: Braze, Google AIza tree, Azure AD,
  server-creds/Supabase, dotCMS/Elasticsearch, Zeta/PushPlanet, Salesforce SFMC,
  Stripe, the source-control/messaging/infra battery (AWS/GitHub/GitLab/Slack/
  SendGrid/Shopify/Twilio/OpenAI/Databricks), plus the weak supporting keys.
  Open on any live service credential.
- `references/source-control.md` — `.git`/`.svn`/source maps/leaked source; mine
  history for live secrets, then exploit them.
- `references/logs-debug.md` — debug logs with live tokens/passwords/reset links;
  exercise the live ones read-only.
- `references/pii-data.md` — bulk PII datasets; prove one cross-boundary read.
- `references/artifacts-config.md` — env/config/backups/object storage; when a
  file carries live cloud/DB creds, call the service.
- `references/client-local-storage.md` — desktop/mobile/browser secret storage.
- `references/case-patterns.md` — generalized exposed-secret technique shapes.
- `references/plays.md` — the eight plays as they ran in **d0x's own 22 reports of this class**, with the outcome of each. This class has the corpus's worst conversion rate — 13 of 22 came back duplicate or informative — and that file is the record of which side each landed on and why.
- `references/case-index.md` — those 22 by play, host, severity and state, with corpus paths. Read it at DEDUP, before spending a turn.
- `../_shared/references/output-contract.md` — where results go: the
  notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim`
  dedup key, and the severity enum.
- `../_shared/references/tooling.md` — what is installed on this host, what is
  not, and the install line for each missing binary.

## Triggers

- API keys/tokens/bearer strings/JWTs/private keys with a recognizable
  prefix/host: `BRAZE_REST_API_KEY` (UUID), `AIza...`, `sk_live_`/`rk_live_`,
  `sb_secret_`/`service_role`, `client_id`+`client_secret`+`*.onmicrosoft.com`,
  `key_live_`, `CONTENTFUL_TOKEN`, `x-dot-server`, `pushplanet`/`USER_GUID`,
  classic `qs=` hex on `*.exacttarget.com`;
- an SSR/Axios error page echoing `auth.username/password` or a backend `url`;
- `.git/HEAD`, `.git/config`, `.git/index`, `.svn/entries`, source maps,
  unminified source, backup archives;
- `.env`, `config.php`, `settings.py`, `database.yml`, `web.config`, kubeconfig,
  docker-compose, Terraform state, CI/deploy logs;
- debug logs / `loglevel=debug` / LDAP/OAuth/SAML logs leaking live tokens,
  passwords, reset links, session cookies, presigned URLs;
- bulk PII/customer records/documents/support tickets accessible to an
  unintended actor;
- browser/mobile/desktop secret storage, vault/biometric keys;
- public object buckets, indexed directories, exposed backups/exports.

## Safety Rules (the safe ladder, not a stop sign)

- **Do use the discovered credential — read-only, own-context.** Mint the token,
  read its scopes, call a non-PII endpoint (rung 1). That is the finding, not a
  violation. See `../_shared/references/safe-ladder.md`.
- Enumerate permissions via **empty/invalid bodies** and read the error — never
  by mutating real data.
- **Prove the scale, don't hoard it.** One or two records prove the class; state scale by
  inference. Do not dump datasets, clone large repos, or bulk-download buckets.
- Prove writes/deletes/financial actions only on **operator-owned or synthetic**
  objects, and revert. Writes/other-user-data on prod → not attempted: ask d0x directly before executing
  (rung 5).
- If RoE restricts cross-tenant/PII testing to UAT/OAT, do the full proof there
  and infer prod impact (rung 4).
- Store raw evidence under `targets/<program>/notes/`; leads/reports redact
  PII/secrets and cite the local note path. **Always flag the leaked key for
  rotation.**
- Report the key against the **brand asset** where it was exposed, not the vendor
  API host (Zeta lesson: a report Bug-URL'd to `jsapi.pushplanet.com` closed
  Out-of-Scope; re-point it at `preferences.email.<brand>.com`).
- **Scope is a safety boundary, not a hunting filter.** Dial only hosts the
  program authorized; a victim id, a foreign org id, or an internal host inside
  the path/query/body/header is always allowed — only the connection target is
  gated. If a host is genuinely out of scope, pivot surface. The vendor API host
  (`rest.<cluster>.braze.com`, `login.microsoftonline.com`, `jsapi.pushplanet.com`)
  is where the *call* goes; the in-scope brand asset is where the *report* points.

## Algorithm

1. Classify the exposure surface (key/credential, `.git`, log, config, artifact,
   dataset, source map, local storage, bucket).
2. Read the discovery context (Method step 0) — sibling keys, base URL, usage.
3. Identify the service by prefix/host; resolve its tier against "Verdict tiers"
   above. SKIP → drop silently. PURSUE-WEAK → test it, record the result in
   `notes/`, hold it for a chain. PURSUE → continue.
4. **Call the service API read-only (rung 1)** — mint/validate, read scopes and
   one non-PII object. Enumerate perms with empty-body error probes.
5. Escalate only as far as needed to prove PII/data/compute/infra access
   (rungs 2–4). Capture minimal proof: request, redacted response, granted
   scopes, field names, one sample, access state, negative control.
6. Rank by impact; lead with the highest.
7. Write the lead to `targets/<program>/leads/` in the format in
   `../_shared/references/output-contract.md`; validate with `validation`; draft
   with `report-writing`.

## Evidence to capture

Per key, before you promote anything:

- the exact URL / path / file / storage location where the secret leaked, and the
  **brand asset** it belongs to (that, not the vendor API host, is the report target);
- the service identified by prefix/host, and the SKIP / PURSUE-WEAK / PURSUE verdict
  you applied;
- the API call you made and the redacted response proving impact — granted scopes, a
  minted token's `aud`/`roles`/`tid`, or one bounded sample record;
- the permission-probe result (empty/invalid body -> param-validation error = granted,
  vs `Access Denied` = not granted);
- the access state and a **negative control** (the same call without the key -> denied);
- the sample count and the bounded-proof statement, with scale by inference, never exfil;
- the raw capture path under `targets/<program>/notes/`;
- a **rotation note** for the leaked key.

## Confirmation Oracles

Strong (PURSUE — exploit now):

- a service key/token whose API returns live data, scopes, or a minted token;
- Braze `/users/export/ids` returns real PII/custom-attributes;
- Google `AIza` validates on `/v1beta/models` and `/v1beta/files` is non-empty;
- Azure `client_credentials` mints a JWT with reachable `roles`/`aud`;
- SSR error leaks backend Basic-Auth creds that authenticate (401→200);
- unauth `/api/es/search` returns indexed config/credential files;
- Zeta `GetSubscriber` returns a subscriber's PII for an arbitrary `email=`;
- `.git`/source map reconstructs source exposing a live secret;
- debug log contains a live token/password/reset link that authenticates.

Weak / skip:

- public-by-default key (Maps/Sentry/Datadog/analytics/`pk_`/Mapbox/Algolia) —
  drop silently;
- fake/example/placeholder token clearly marked as documentation;
- **PURSUE-WEAK** (Contentful Delivery-only, Unleash flags with no live coupon, Branch
  `key_live_`, Bugsnag/Amplitude event injection) — test and record, chain-only, never
  lead;
- source map/config with no live secret or routes;
- local-storage issue requiring admin/root with no sensitive key exposure.

Not findings:

- a key you never exercised ("existence") — go call the API;
- secrets intentionally public and scoped for public use;
- data accessible only to its intended owner with no bypass;
- bulk-PII *claim* with no sampled, access-stated proof.

## Severity Guidance

- **critical**: server key exporting mass/financial/identity PII (Braze with
  financial custom-attributes, Zeta retail/finance profiles, SFMC cross-tenant
  subscribers); cloud/admin credentials or minted tokens reaching Management/
  Vault/Storage/internal APIs; secrets that chain to RCE or tenant escape;
  Stripe `sk_live_`.
- **high**: valid credentials with real data read, Google `AIza` file/corpora
  data exposure, private source with secrets, sensitive PII at scale, auth logs
  with live tokens, local vault/key material.
- **medium**: limited secrets, internal source, small low-sensitivity PII,
  generation/quota abuse framed with $-cost.
- **low**: metadata/source exposure without credentials or sensitive data.

### What 22 of d0x's own reports in this class actually did

Full write-ups in `references/plays.md`; the index in `references/case-index.md`.
**13 of 22 came back duplicate or informative** — the worst conversion rate of any
class in the corpus. Four things the tiers above do not say:

**The dividing question is not "is this secret."** It is whether the key **reads data,
mints compute, or writes to something someone trusts.** Sorting the corpus by that
predicts the outcomes almost exactly: reads customer records → Critical · deletes real
records → Critical · writes into something *trusted*, such as links on the brand's own
short domain → Medium and worth it · writes into analytics → duplicate · reads ordinary
CMS content → informative.

**The chained findings outperform the found ones.** Every top-tier result needed a
second step: the credential was *inside* a config file *inside* an unauthenticated
search index; *inside* a serialized HTTP-client error object; *inside* a URL preserved
by a public web archive. What everyone finds by grepping bundles came back duplicate.

**Two Criticals were still duplicates.** Being right is not enough here. Grep the
ledger and the corpus for the primitive **and** the vendor before starting.

**Prove the key belongs to the in-scope asset.** The one Critical that resolved ties a
third-party vendor workspace to the program by quoting the endpoint hardcoded in the
in-scope app's own resources. Without that step a vendor key is out of scope by default.

**A sensitive file at a public URL is not a finding.** The one not-applicable is exactly
that. The comparable report that *did* resolve proved an inconsistency instead — most
documents in the same archive are redacted, two are not. Find the control that failed,
or find the sibling that works.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- `js-source-to-sink`: needs to mine more bundles/source maps for keys/endpoints.
- `cloud-exploitation`: Cognito/S3/DynamoDB/IMDS/Azure escalation from a harvested
  credential.
- `idor-bola`: exposed data needs an object-id/tenant-id swap to reach.
- `auth-flow-bypass`: reset links, sessions, OAuth tokens, MFA/recovery secrets.
- `rce-hunting`: exposed secret/source chains to execution.
- `validation`: confirm the proven-impact claim before reporting.
- `report-writing`: draft the finding once impact is proven and deduped.

## Dedup — reuse the technique, not a closed report

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

Also dedup against this session's `findings/`. The *exploitation technique* (the per-service play, the read-only API
proof) is reusable across every target; a *specific submitted finding* — the same
key/service already reported on this target — is CLOSED. On a match, change angle:
mine the next surface, identify the next service, find the next distinct secret.
Never re-report a key already in the corpus.

**The rule in one line:** a leaked secret is rung 0 — the finding is the data /
PII / infra proven by the read-only API call made with it. Never stop at "it's
exposed."
