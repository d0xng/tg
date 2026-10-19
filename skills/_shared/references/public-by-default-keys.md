# Public-by-Default Client-Side Keys — Skip-List vs. Pursue-List

Shared reference. Every skill that surfaces a "leaked" key imports this before
reporting one.

A key found in a JS bundle, HTML, mobile app, or public config is **not
automatically a finding**. Half of these keys are *designed* to ship to the
browser — reporting them is informative, pays zero, and wastes d0x's time. The
other half unlock data / compute / PII from the server side and ARE worth
chasing to proven impact.

**Rule:** identify the key by prefix/host, look it up in the table, and act on the
verdict. If it's SKIP, do not test it, do not chain it, do not surface it — move
on silently. If it's PURSUE, do not stop at "found it" — call the service's API
and prove impact via the safe ladder (`safe-ladder.md`).

---

## The table

| Key / token | Identify by | Verdict | Why |
|---|---|---|---|
| Sentry DSN | `https://<hash>@o###.ingest.sentry.io/...`, `Sentry.init` | **SKIP** | Public error-reporting endpoint by design. Injecting events is informative, not payable. |
| Datadog client token | `pub<hex>`, `DD_CLIENT_TOKEN`, RUM `clientToken` | **SKIP** | Browser RUM/telemetry token, meant to be public. |
| Amplitude / Mixpanel / Segment **write** keys | `amplitude.getInstance`, Mixpanel project token, Segment `writeKey` | **SKIP** | Client-side analytics write keys; inflating counters is informative only. **A Segment workspace/management token is NOT this — see the caveat below.** |
| reCAPTCHA site key | `6L...` in `data-sitekey` / `grecaptcha.render` | **SKIP** | The *site* key is public by definition (the secret key is not). |
| Stripe publishable key | `pk_live_...`, `pk_test_...` | **SKIP** | Publishable keys are meant for the browser; they cannot move money or read data. |
| Mapbox public token | `pk.<base64>` (Mapbox), `mapboxgl.accessToken` | **SKIP** | Public map-tile token by design. |
| Algolia search key | `algoliasearch(appId, <searchKey>)`, search-only key | **SKIP** | Search-only API key is intended to be public. |
| Google Maps API key | `AIza...` used in Maps JS / `maps.googleapis.com` | **SKIP** | Maps browser key is public by design. **Caveat below.** |
| PostHog project key | `phc_[A-Za-z0-9]{40}` | **SKIP** | Client-side capture key; ingesting events is informative only. |
| Google Analytics id | `G-XXXXXXX`, `UA-XXXXXX-N` | **SKIP** | A measurement id, not a credential. |
| LaunchDarkly client-side id | 24-hex in `LDClient.initialize(...)` | **SKIP** | Client-side id is public by design. (An `sdk-`/`api-` **server** key is not — that one is PURSUE.) |
| Cloudflare Turnstile sitekey | `0x4AAAAAAA…` in the widget | **SKIP** | Sitekey is public by definition; the secret key is not. |
| — | | | |
| Google API key (non-Maps) | `AIza...` reaching Generative Language / Gemini / other billable APIs | **PURSUE** | Unlocks compute/data on d0x's dollar; test the enabled APIs. See exposed-secrets + Gemini tree. |
| Braze REST API key | UUID `BRAZE_REST_API_KEY`, `rest.iad-*.braze.com` | **PURSUE** | Server key: export user PII, send campaigns. Top converter. |
| Azure AD client credentials | `client_id` + `client_secret` + `*.onmicrosoft.com` / tenant id | **PURSUE** | Mint a token, hit Graph — data/PII/infra. |
| dotCMS / server creds | `x-dot-server`, exposed admin/API creds, DB/service passwords | **PURSUE** | Direct server access / data. |
| Supabase secret key | `sb_secret_...`, `service_role` JWT | **PURSUE** | Bypasses RLS — full DB read/write. (Anon `sb_publishable_`/`anon` key is NOT this — that's client-side.) |
| Stripe secret key | `sk_live_...`, `sk_test_...`, `rk_live_...` | **PURSUE** | Full account API: charges, customers, PII. Prove read-only (list your own test objects) first. |
| AWS access key id | `AKIA[0-9A-Z]{16}` (long-lived), `ASIA[0-9A-Z]{16}` (STS temp) | **PURSUE** | With the matching secret, full IAM reach. Prove with `sts get-caller-identity` only (rung 1), then stop. → `../../cloud-exploitation/references/iam-creds.md`. |
| GitHub token | `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_` | **PURSUE** | `GET https://api.github.com/user` + read the `X-OAuth-Scopes` response header — that header alone proves scope. Private repos/org data. |
| GitLab PAT | `glpat-[A-Za-z0-9_-]{20}` | **PURSUE** | `GET /api/v4/personal_access_tokens/self` → scopes; then `/api/v4/projects?membership=true`. |
| Slack token | `xoxb-` `xoxp-` `xoxa-` `xoxr-` `xoxs-` | **PURSUE** | `POST https://slack.com/api/auth.test` → team + user + scopes. Bot/user tokens read channels and files. |
| SendGrid API key | `SG.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | **PURSUE** | `GET https://api.sendgrid.com/v3/scopes` → granted scopes; a `mail.send` scope = send-as-the-brand (phishing chain). |
| Shopify token | `shpat_` `shpss_` `shpca_` (32 hex) | **PURSUE** | `GET /admin/api/2024-10/shop.json` `X-Shopify-Access-Token:` → store data; customer/order scopes = PII. |
| Twilio | `AC[0-9a-f]{32}` + auth token, or `SK[0-9a-f]{32}` | **PURSUE** | `GET https://api.twilio.com/2010-04-01/Accounts/<AC…>.json -u AC…:<token>` → account; call/SMS logs are PII. |
| OpenAI / Anthropic | `sk-`, `sk-proj-`, `sk-ant-` | **PURSUE** | Billable compute on the target's account. `GET https://api.openai.com/v1/models` / `POST https://api.anthropic.com/v1/messages` with a 1-token request — one call proves live, then stop (rung 2b). |
| Databricks PAT | `dapi[0-9a-f]{32}` | **PURSUE** | `GET /api/2.0/preview/scim/v2/Me` → identity; workspace/data reach. |

---

## PURSUE-WEAK — real payload, chain-only, never lead

These keys have a working exploitation payload but almost never convert alone.
They are **not SKIP** (do not "leave them silently") and **not lead-worthy**: test
them, record the result, and only report when a chain attaches. Full payloads:
`../../exposed-secrets/references/saas-key-exploitation.md` "Weak / supporting keys".

| Key | Identify by | What it actually does | Reportable when |
|---|---|---|---|
| Branch.io | `key_live_` / `key_test_` | `POST api2.branch.io/v1/url` mints links on the brand's own `go.<brand>.com` with an attacker `$fallback_url` | chained to credential/token theft (the link is brand-trusted) |
| Contentful | `CONTENTFUL_TOKEN` + `CONTENTFUL_SPACE` | Delivery token = published entries (informative). **`preview.contentful.com` token = unpublished drafts** | the Preview token exposes drafts/embargoed content |
| Unleash | `*:production.<hex>` | `GET /api/frontend` `Authorization: <key>` → flags carrying coupons/pricing | a leaked coupon or pricing flag is live at checkout |
| Bugsnag / Amplitude | 32-hex `apiKey` + `notify.bugsnag.com` / `AMPLITUDE_KEY` | event injection, cost inflation | essentially never — supporting evidence only |

**Segment caveat (same-string, opposite-verdict — the `AIza` trap again):** a Segment
**`writeKey`** is SKIP (client-side analytics write). A Segment **workspace /
management API token** (`sgp_…`, used against `api.segmentapis.com`) is **PURSUE** —
it reads every source and destination in the workspace, *including their configured
credentials*. Resolve by which API the token authenticates against, never by the word
"Segment".

---

## How to tell the two `AIza...` cases apart

`AIza...` is a Google **API key** prefix used by *many* Google services. The
prefix alone decides nothing — **which API it's authorized for** does.

- If the only place it's used is Maps / Places / Static Maps → **SKIP** (public
  Maps key).
- If it can reach a **billable data/compute API** (Generative Language / Gemini,
  translation, vision, etc.) → **PURSUE**: enumerate the enabled APIs and prove
  impact. See the `exposed-secrets` skill and the Gemini `AIza` tree.

Same string, opposite verdict — always resolve by *reachable API*, not prefix.

---

## Proving impact on a PURSUE key

Existence is not a finding. Once identified as PURSUE:

1. Identify the service by prefix/host.
2. Climb the safe ladder: mint the token, **read back granted scopes** and one
   **non-PII** object first (`safe-ladder.md`, rung 1).
3. Escalate only as far as needed to prove PII/data/compute access — read-only,
   own-context, UAT if RoE requires — then stop and report.

## SKIP means silent

For a SKIP key: leave it, do not test it, do not mention it in output. Surfacing
"I found a Sentry DSN / Stripe pk / Maps key but it's informational" is itself the
noise this list exists to remove. Spend the tokens on a PURSUE key or a different
boundary.

A **PURSUE-WEAK** key is different: test it, log the result in `notes/`, and hold
it until a chain attaches. Do not report it standalone, and do not drop it
silently either — it is the second half of somebody else's chain.

## SKIP the key, keep the capability

One exception that is not an exception to the silence rule: a public **identity** key is
the intended input to the sign-up API behind it, and creating an account with it is a
legitimate primitive even though the key itself is worth nothing.

| Public key | The call it authorizes | What it buys |
|---|---|---|
| Firebase / Google `AIza…` (Identity Toolkit) | `POST identitytoolkit.googleapis.com/v1/accounts:signUp?key=…` | an account, and an `idToken` the app accepts as its own bearer |
| Supabase anon / `sb_publishable_…` | `POST /auth/v1/signup` | same, plus whatever RLS lets that role read |
| Cognito app-client id | `SignUp` / `InitiateAuth` (unauthenticated) | an account; `UserConfirmed:true` means no email step |

Registering an account is not the finding either. The finding is what the platform grants
that account for free — most often membership of an organisation inferred from the
**unverified** email domain, which is
`../../tenant-isolation/references/tenant-vectors.md` §6, and otherwise the Cognito
attribute chain in `../../auth-flow-bypass/references/cognito-auth.md` §D.

So: still never report the key. Do not stop at it either — ask what an account it can
mint is automatically entitled to.
