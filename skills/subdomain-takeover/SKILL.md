---
name: subdomain-takeover
description: "Assess subdomain takeover, dangling CNAME or NS delegation, stale DNS, unclaimed third-party resources, broken-link hijacking, and expired trusted assets. Use when DNS points to a missing provider resource, a delegated zone fails authoritatively, a provider exposes an unclaimed-resource fingerprint, or the user asks about SDTO. Confirm provider-specific claimability without claiming the resource, then evaluate cookie, OAuth, or CSP trust chains."
---

# subdomain-takeover — claim what the target forgot to, then chain it to ATO

A subdomain takeover exists when a DNS record points at a third-party service
whose underlying resource is **unclaimed**, so you can register it and serve
content on the target's *trusted* subdomain. d0x supplies the subdomain list
(his recon); your job is to **resolve, fingerprint, verify claimability, claim
non-destructively, and prove real impact**.

**A dangling record is rung 0 — it is NOT the finding.** A matching fingerprint
proves nothing until you (a) confirm the provider still lets you register the
resource and (b) show what that trusted `*.target.com` unlocks. Programs (and
d0x) pay for the **chain** — a stolen `.target.com` session cookie, a captured
OAuth `code`, a CSP-trusted script running in the parent app — not for "I served
a page." Bare page-hosting is often Medium; the chain is what makes it High.
Climb the shared safe ladder (`../_shared/references/safe-ladder.md`):
read-only fingerprint → claim in your own provider account → benign marker →
demonstrate the chain minimally → stop and report. **Do not use subjack** — it
false-positives on patched providers and never proves claimability; use `dig` +
`curl` + the catalog references below.

> **ALREADY REPORTED — reuse the technique, not the report.** d0x's submitted
> corpus already contains broken-link-hijacking / dangling-asset takeovers on
> some targets. On **those targets that finding is CLOSED** — do not
> re-discover the same dangling record and resubmit. Apply the methodology to
> **new** subdomains/targets.
>
> Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Read-on-demand references

Keep the trigger map (below) internalized; open a reference when you commit to a
candidate.

- `references/catalog.md` — the full **provider → CNAME hint → fingerprint**
  table for resources vulnerable **today**, PLUS the **patched / edge-case**
  list (GitHub Pages, Heroku, Shopify, CloudFront, Fastly, Zendesk, Statuspage,
  GitLab Pages) that die on manual claimability. Do NOT report those without
  extra proof. NXDOMAIN alone is never proof.
- `references/ns-delegation.md` — **dangling NS → re-creatable cloud DNS zone**
  (Route 53 / Google Cloud DNS / Azure DNS / DigitalOcean / Vultr / Linode):
  full-zone control (point A/CNAME/MX anywhere, issue TLS certs) — the highest
  impact. Also the SPF `include:` / MX takeover → email spoofing vector.
- `references/convert-chains.md` — **how you make it pay**: session-cookie theft
  on a `Domain=.target.com` cookie, OAuth/SSO `redirect_uri`/callback capture →
  token/ATO, CSP `script-src *.target.com` trust → script exec in the parent
  app, framing/`postMessage` trust, and secret/API-key capture from apps that
  POST to the subdomain. This is the difference between Medium and High.
- `../_shared/references/output-contract.md` — where results go: the
  notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim`
  dedup key, and the severity enum.

Also import: `../_shared/references/safe-ladder.md` (how far to climb — claim in
your own account, benign marker, minimal chain proof, revert) and
`../_shared/references/public-by-default-keys.md` (if the chain captures a key
POSTed to the subdomain, SKIP the public-by-default ones silently and only
pursue the data/PII/compute-unlocking ones).

## Method (per subdomain in d0x's list)

If the scope is still a bare wildcard and there is no host list yet, expand it
first — `subfinder -d target.com -all | httpx -silent > targets/<program>/hosts.txt`
— then work that file. This skill consumes a resolved host list.

1. **Resolve every record type — the record type IS the vector.**
   ```bash
   dig +short CNAME sub.target.com          # CNAME → third-party provider?
   dig +short A     sub.target.com          # A → cloud IP no longer owned?
   dig +short NS    sub.target.com          # delegated to a cloud DNS zone?
   dig +short TXT   target.com | grep spf   # SPF include: → takeoverable host?
   dig +short MX    target.com              # MX → takeoverable mail host?
   ```
2. **Spot the dangling signal.** A CNAME/NS to a provider whose apex answers
   `NXDOMAIN`; an A record on a cloud IP the target no longer owns; or the
   provider serving its own "unclaimed / not found / claim this" page.

   > **`+short` is for record VALUES only — it hides the rcode.** SERVFAIL,
   > REFUSED, NXDOMAIN and an empty answer all print nothing and exit 0, and
   > SERVFAIL vs NXDOMAIN are opposite verdicts here. Read any status with
   > `dig +noall +comments <name> <type>` (or `dig … | grep -E 'status:'`),
   > never from an empty `+short`. See `references/ns-delegation.md` §Detection.
   > **A host that answers `200` with a real application is not automatically a
   > negative.** Check *whose* application it is before moving on — an unrelated ASN
   > and a TLS certificate naming another company mean the subdomain is claimed by a
   > third party, which carries the same cookie/CSP/OAuth exposure as a takeover and
   > is permanent. `references/convert-chains.md` §"The sibling state".

3. **Fingerprint over HTTP — the CNAME names the provider, the body confirms
   it's unclaimed.**
   ```bash
   curl -sSL -m 15 -H 'Host: sub.target.com' https://sub.target.com \
     | grep -iF '<fingerprint string from catalog.md>'
   curl -s -o /dev/null -w '%{http_code}\n' https://sub.target.com
   ```
   Match the CNAME provider + body/status against `references/catalog.md`.
4. **Verify claimability MANUALLY (this is where most false positives die).** A
   matching fingerprint is necessary, not sufficient. Confirm the provider still
   lets you register that *exact* name/resource with no ownership proof. Most of
   the classic providers **patched** (domain verification / TXT challenge) — see
   the patched list in `references/catalog.md`. If claiming needs a DNS
   verification token the target controls, it is **not** takeoverable.

   > **Claiming the resource is rung 5.** Registering the dangling name at the
   > provider creates real state on a third party under the target's brand.
   > **Never claim unilaterally.** Prove claimability read-only first (NXDOMAIN +
   > the provider's "not found / claim this" fingerprint + the provider's
   > documented claim mechanism). If the program requires an actual claim, the
   > primary agent asks d0x directly with the exact registration step before
   > executing it, then records the result in the report.

5. **If a claim were authorised, it would be non-destructive.** Register the
   resource in **your own** provider account and serve a **benign marker only** —
   a `poc-<reportid>.txt` text file or one harmless HTML line. Never serve
   malicious content; never leave it live past the PoC; take it down after
   capture. If the program forbids claiming/hosting, the dangling CNAME +
   fingerprint + written provider-claimability analysis is the evidence.
6. **CONVERT — build the actual chain (`references/convert-chains.md`).** "I can
   host a page on `*.target.com`" is the primitive, not the impact. Pick the
   chain the parent app exposes (cookie theft / OAuth capture / CSP-trust /
   email spoof) and demonstrate it end-to-end against **your own** test session.

## Trigger map — record/marker → vector → first move

| You see (marker) | Vector | First non-destructive move | Reference |
|---|---|---|---|
| CNAME → provider, apex NXDOMAIN or "not found" body | Dangling CNAME | `curl` fingerprint vs catalog, then check provider claim flow | `catalog.md` |
| `dig NS` → `ns-*.awsdns-*` / `ns-cloud-*.googledomains.com` / `*.azure-dns.*` and SERVFAIL/no SOA | Dangling NS → cloud DNS zone | Query the delegated NS directly for SOA; REFUSED/SERVFAIL = zone gone | `ns-delegation.md` |
| A record on a cloud IP that no longer serves the app | Stale A | Re-provision the same IP/resource on that provider (if re-assignable) | `catalog.md` |
| Apex/subdomain returns NXDOMAIN and the name itself is registerable | NXDOMAIN apex | Confirm the base name is actually purchasable, not just non-resolving | `catalog.md` |
| SPF `include:` / MX → a takeoverable host | Email spoofing | Take over the included host → send DKIM/SPF-passing mail as @target | `ns-delegation.md` |
| Page links to an expired third-party asset (JS/handle/CDN) | Broken-link hijacking | Re-register the expired asset/handle → serve script into the page | `convert-chains.md` |

## Converts? (severity reality — grade honestly, lead with the chain)

Hosting content on a trusted `*.target.com` is the primitive; severity comes
from what the parent app trusts about that subdomain:

- **High** — **session/cookie theft**: parent sets cookies with
  `Domain=.target.com` (no `__Host-` prefix). Your page on the taken-over
  subdomain reads `document.cookie` and exfiltrates → account impact. Prove it
  reading **your own** test session's cookie.
- **High** — **OAuth/SSO `redirect_uri` or callback** registered on the
  takeoverable subdomain: point it at your page, capture the `code`/`access_token`
  from the query/fragment, exchange → ATO. (grep the JS for `redirect_uri=`,
  `client_id`, allowed-callback lists.)
- **High** — **CSP / `script-src` trust**: the parent app's CSP allows
  `script-src *.target.com` (or explicitly the taken-over host). Host your
  script there → it executes in the parent origin, defeating the CSP that would
  block an external attacker → effectively stored XSS / data read on the main app.
- **High** — **NS-delegation takeover**: full DNS control of the subdomain
  (issue TLS, MX, A/CNAME anywhere). Beats a normal CNAME takeover; see
  `ns-delegation.md`.
- **Medium** — email spoofing via SPF/MX takeover (phishing that passes SPF);
  secret capture where non-sensitive; a bare "trusted-domain phishing/malware
  host" with no cookie/OAuth/CSP trust to chain.
- **Skip / not a finding** — a dangling CNAME to a **patched** provider you can't
  actually claim; NXDOMAIN with the base name not purchasable; "I could serve a
  page" with zero parent-app trust to exploit and no email/OAuth angle. Don't
  inflate these into a High.

Validate anything High with `validation` before promoting to `findings/`.

## Evidence checklist (the triager re-proves it — make it self-contained)

Every item copy-pasteable, captured as you go into `targets/<program>/notes/`:

- **The dangling signal** — the `dig +short CNAME/NS/A` output, plus the apex
  `NXDOMAIN` or (for NS) the delegated-NS `SERVFAIL`/`REFUSED` on SOA.
- **The fingerprint** — the `curl` body match and the status code, named against
  the catalog entry (say which provider).
- **Claimability confirmed** — exactly why the provider still lets you register
  it (which claim flow, and that there is no ownership challenge); or, if you
  claimed it, the provider-side proof you now own the resource.
- **Negative control** — the same subdomain *before* claiming served the
  provider's unclaimed page, proving the resource was genuinely dangling and not
  already yours.
- **Non-destructive claim proof** — the benign marker served on the trusted host
  (`curl https://sub.target.com/poc-<reportid>.txt` returning your marker); for
  NS, the public resolution of your benign TXT/A on the trusted name.
- **The chain, end-to-end against YOUR OWN session** — the cookie exfil hit on
  your OOB listener with your own cookie plus one authenticated replay; OR the
  captured OAuth `code` plus the token exchange reaching your own account; OR the
  CSP-trusted script executing in the parent origin with one benign in-origin read.
- **Cleanup note** — state that you released the claimed resource / removed your
  zone after capture.

Redact the captured session value in anything that leaves `notes/`
(`cookie=<redacted, len=NN>`) while keeping the `Domain=.target.com` attribute
and the OOB hit visible — the attribute is the evidence, the value is not.

Then write the lead or finding to `targets/<program>/` per
`../_shared/references/output-contract.md`. Use **Group:** `third-party`
and keep the claim string stable — name the **subdomain + record type + provider
+ chain** ("SDTO assets.target.com dangling-CNAME S3 → cookie theft"), never
just "subdomain takeover", or the same candidate reads as new next session.

## Non-destructive rules (every step — the safe ladder in practice)

- **Read-only fingerprint first** (`dig`/`curl`); never claim — confirm claimability
  read-only; if an actual registration is required, ask d0x directly with the exact step before executing (rung 5).
- **Claim in YOUR own provider account**, serve a **benign** marker only, and
  **take it down** after capturing the PoC. Never serve malware/phishing to real
  users; never leave the resource claimed.
- **NS/zone proof:** demonstrate control with a benign TXT/A record you set;
  never disrupt the target's real resolution or delete their records.
- **Chain proof uses YOUR OWN test session** — read *your* `.target.com` cookie,
  capture *your* OAuth `code`, execute the CSP-trusted script against *your*
  logged-in test account. Never phish, cookie-steal, or capture a real user's
  session.
- The provider control plane you use to *claim* (the AWS console, the Route 53
  API, a vendor dashboard) is **your own** infrastructure, not a target host —
  dialing it is expected, not an out-of-scope action. The in-scope host is the
  `*.target.com` subdomain you fingerprint and serve the marker on.
- If the chain captures a leaked key POSTed to the subdomain, run it past
  `../_shared/references/public-by-default-keys.md` — SKIP the public-by-default
  ones silently; only pursue the data/PII/compute keys (hand to `exposed-secrets`).

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- Chain captures a live service key/secret POSTed to the subdomain →
  `exposed-secrets` (identify + call the API to prove impact).
- CSP-trust / broken-link chain lands you executing script in the parent origin
  and you want the DOM/postMessage sinks → `js-source-to-sink`.
- The OAuth `redirect_uri` you captured belongs to a cloud IdP (Cognito/Azure) →
  `cloud-exploitation` to escalate the stolen token.
- About to claim High / ATO → `validation` re-proves first.
- Confirmed bug → `report-writing`.
