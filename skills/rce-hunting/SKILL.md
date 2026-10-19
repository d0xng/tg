---
name: rce-hunting
description: "Hunt remote code execution through command or argument injection, SSTI and expression languages, unsafe renderers and converters, headless-browser debugging, file-write chains, CI/CD inputs, dependency confusion, and known code-execution surfaces. Use when parameters reach system tools, templates evaluate expressions, uploads enter converters, a renderer exposes browser internals, or an existing SSRF or write primitive can reach execution. Prove only a benign non-persistent command."
---

# rce-hunting — the finding is a live `id` on the box, not the sink you found

RCE is the top of the ladder. In bug bounty you almost never get a bare
`eval(user_input)` — RCE comes from **chaining primitives**: a headless renderer
becomes file read via the Chrome debug protocol; an SSRF becomes RCE via IMDS ->
IAM creds -> deploy pipeline; a file write becomes RCE via a loaded path. **Think
in chains, and drive each chain to a benign command that runs on the server.**

**A discovered sink / vulnerable version is rung 0.** "wkhtmltopdf is old",
"`{{7*7}}` returned 49", "there's a `cmd=` param", "`x-powered-by: Next.js`" —
none of these are findings. The finding is the proof: `id` -> `uid=1001(nextjs)`,
`whoami` -> `root`, the contents of `/var/run/secrets/kubernetes.io/serviceaccount/token`,
`/etc/passwd` reflected in the rendered PDF. **Running that one benign command is
the deliverable.** Never surface "this could be RCE" and hand off — you are the
one who lands the command.

## The prod proof is a benign command — DROP "prefer local/staging"

This skill's black-box default is **not** source review or a local repro. It is a
single **non-mutating** command executed on the production target and its output
read back. That is rung 1 of the shared safe ladder
(`../_shared/references/safe-ladder.md`) — read-only, own-context, minimal — and
it is exactly what programs pay for. Import the ladder and climb it:

- **Rung 1 (read-only, the default proof):** `id`, `whoami`, `hostname`, `uname -a`,
  `cat /etc/passwd`, `cat /proc/self/environ`, read the k8s SA token. These do not
  mutate anything and prove code execution / arbitrary file read outright. This is
  where almost every RCE proof lives — take it and stop.
- **Rung 2 (own/anon context):** run the command from an owned tenant/session/repo;
  write a benign marker file (`__poc_<rand>__`) to a path **you** own, then read it
  back. Never touch another tenant's data.
- **Rung 3 (prove the scale):** one command, one file. Proving you can read `/etc/passwd`
  proves you can read `/etc/shadow`; say so by inference, do not dump the box.
- **Rung 4 (UAT):** if RoE restricts intrusive/service-affecting testing to
  `*-uat`/`*-oat`, land the full chain there; on prod stop at the rung-1 benign
  read and state prod-equivalent impact.
- **Rung 5 (not attempted — ask d0x directly before executing):** reverse shells, persistence, writing to a **real**
  loaded path, code-push/deploy with harvested creds, deleting/modifying data,
  reading another real user's data. Carry the exact command in the verdict; revert
  anything you change.

Local/staging/vendor-sandbox repro is a **fallback for when the payload is
genuinely unsafe to fire on prod** (a DoS-shaped CVE, a parser bomb, a destructive
write with no benign variant) — not the default. If a benign `id` is possible on
prod, run it.

> **Reuse the technique, not a past report.** The Next.js RSC, Perforce, and
> headless-Chrome chains below are public prior art and recurring converters —
> apply the methodology to **new** targets. Next.js RSC especially is
> mass-exploited — **be first or skip**.
>
> Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Read-on-demand references

Load the one that matches the surface you committed to. Keep the trigger map
internalized; open a reference when you commit to a class.

- `references/headless-chrome-cdp.md` — **a high-yield RCE chain.** HTML-to-PDF /
  screenshot / thumbnail renderer -> confirm JS in `HeadlessChrome` UA -> reach
  the localhost DevTools debug port (30000-50000 / 9222) -> `/json` WebSocket ->
  `Page.navigate file:///...` + `Runtime.evaluate` / `Page.printToPDF` -> read the
  k8s SA token, `~/.aws/credentials`, `/proc/self/environ`. The renderer is also a
  full SSRF -> pivot to IMDS.
- `references/nextjs-rsc-rce.md` — Next.js RSC deserialization **CVE-2025-55182**
  (RCE) / **CVE-2025-55184** (DoS). Fingerprint, the safe 2-step probe
  (`Next-Action` text/plain 404 -> multipart 500+RSC body), and the
  `child_process.execSync('id')` prototype-pollution gadget. NEVER fire the DoS
  payload on prod.
- `references/ssrf-to-rce.md` — SSRF -> `169.254.169.254` IMDS (v1 GET / v2
  PUT-token) -> `iam/security-credentials/<role>` -> `sts get-caller-identity` ->
  read-only enum -> (rung 5) code-push via CodeCommit/ECR/Lambda. Hands to
  `cloud-exploitation` for the IAM half.
- `references/template-expression.md` — per-engine SSTI ladder: the `{{7*7}}` /
  `${7*7}` / `<%= 7*7 %>` fingerprint matrix and the exact **RCE** payload for
  Jinja2, Twig, Freemarker, Velocity, ERB, Smarty, Mako, Nunjucks, Spring EL/OGNL.
  Stop at a reflected `id`, not at `49`.
- `references/command-injection.md` — OS command-injection families: separators,
  blind/OOB, timing, and **argument/flag injection** (leading-`-` filenames into
  git/tar/curl/ffmpeg). Concrete payloads and the `id`/OOB/`sleep` oracle.
- `references/upload-converter-parser.md` — ImageMagick (ImageTragick
  CVE-2016-3714, file-read CVE-2022-44268), Ghostscript (`%pipe%`
  CVE-2023-36664 / CVE-2018-16509), ExifTool DjVu **CVE-2021-22204** (Perl-eval
  RCE), LibreOffice/ffmpeg/SVG/wkhtmltopdf. Exact payload shapes + the metadata
  read oracle.
- `references/file-write-to-rce.md` — file write -> RCE escalation: Perforce
  arbitrary write (unset `P4CLIENTPATH`), webshell in webroot, `authorized_keys`,
  cron, systemd, `.bashrc`, DLL hijack, git hooks, Python `.pth`. Prove the write
  on a sentinel path; land `id` only via a benign owned loaded path.
- `references/cicd-build.md` — untrusted PR/fork/package input reaching a build/CI
  run step; `postinstall` hooks; import jobs. Marker in your own fork's CI log.
- `references/k8s-ingress-config.md` — ingress-nginx annotation/snippet config
  injection reaching a controller reload.
- `references/supply-chain.md` — dependency confusion, unclaimed namespaces,
  install-doc RCE. Passive claimability, coordinate before claiming.
- `references/case-patterns.md` — generalized technique patterns + dedup anchors for
  every class above.
- `../_shared/references/output-contract.md` — where results go: the notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim` dedup key, and the severity enum.
- `../_shared/references/tooling.md` — what is installed on this host, what is not, and the install line for each missing binary.

Also import: `../_shared/references/safe-ladder.md` (how far to climb — read it)
and `../_shared/references/public-by-default-keys.md` (when an RCE chain surfaces a
key, SKIP the public-by-default ones silently and PURSUE the rest to impact).

## §0 — Find the execution surface

Grep the JS bundles, HTML, and captured responses already sitting in
`targets/<program>/js/` and `targets/<program>/notes/`; fingerprint the stack:

- **Headless renderer** — any "export/download PDF", "screenshot", "thumbnail",
  "preview URL", "print", "generate invoice/report", HTML-email preview. Injected
  markup that renders -> a `HeadlessChrome/<ver>`, `wkhtmltopdf`, `Puppeteer`,
  `PhantomJS`, or `weasyprint` fingerprint. -> `references/headless-chrome-cdp.md`.
- **Next.js RSC** — `x-powered-by: Next.js`; `content-type: text/x-component`;
  `vary: RSC, Next-Router-State-Tree`; `x-nextjs-cache`/`x-nextjs-prerender`.
  -> `references/nextjs-rsc-rce.md`.
- **Command sink** — params/fields named `cmd`, `command`, `exec`, `host`, `ip`,
  `ping`, `target`, `domain`, `url`, `file`, `path`, `filename`, `args`, `options`,
  `format`; features that run ping/traceroute/dig/nslookup/whois/git/tar/zip/
  ffmpeg/convert. -> `command-injection.md`.
- **Template/preview** — email/report/PDF template editors, "custom template",
  Liquid/Handlebars/mustache in the UI, `{{ }}`/`${ }`/`<%= %>` echoed back.
  -> `template-expression.md`.
- **Upload -> converter** — image/PDF/video/Office/SVG upload processed by
  ImageMagick/GraphicsMagick, Ghostscript, ExifTool, LibreOffice, ffmpeg,
  wkhtmltopdf. -> `upload-converter-parser.md`.
- **File-write / VCS** — Perforce/Git/SVN integration, "import repo", backup
  restore, archive extract (Zip-Slip), any write of an attacker-named/pathed file.
  -> `references/file-write-to-rce.md`.
- **SSRF you already have** -> point it at `169.254.169.254`. -> `ssrf-to-rce.md`.

## Trigger map — surface -> class -> first non-destructive move

| You see | Class | First move (rung-1 proof target) | Reference |
|---|---|---|---|
| HTML-to-PDF / screenshot / thumbnail renderer | Headless Chrome / CDP | Inject markup -> read `navigator.userAgent`; then `fetch('http://localhost:9222/json')` from the render | `headless-chrome-cdp.md` |
| `x-powered-by: Next.js` + RSC headers | Next.js RSC deser | `Next-Action:` 40×`a` text/plain -> `404 Server action not found` | `nextjs-rsc-rce.md` |
| `cmd`/`host`/`ping`/`filename` param to a tool | OS command injection | `; id`, `$(id)`, `` `id` ``, `|id`, `%0aid` -> look for uid output | `command-injection.md` |
| `{{7*7}}`/`${7*7}` echoed as `49` | SSTI | fingerprint engine, then engine-specific `... 'id' ...` | `template-expression.md` |
| Upload hits ImageMagick/Ghostscript/ExifTool | Converter CVE | benign file first; then CVE payload reading `/etc/passwd` into metadata | `upload-converter-parser.md` |
| Perforce/Git/SVN write or archive extract | File-write -> RCE | write a sentinel to a path you own; confirm arbitrary path | `file-write-to-rce.md` |
| SSRF sink you control | SSRF -> IMDS -> RCE | `PUT /latest/api/token` then GET `iam/security-credentials/` | `ssrf-to-rce.md` |

## The four headline chains (drive one to a live command)

**Chain 1 — Headless Chrome -> CDP -> file read -> k8s / cloud creds (high-yield).**
Find a renderer. Prove JS runs in it (render `<script>document.title=navigator.userAgent</script>`
or an OOB `fetch` -> `HeadlessChrome/<ver>`). The render context is a full SSRF and,
if Chrome runs with `--remote-debugging-port`, `fetch('http://localhost:9222/json')`
(or scan 30000-50000) yields a `webSocketDebuggerUrl`. Open it with
`new WebSocket('ws://localhost:<port>/devtools/page/<id>')`, then CDP:
`Page.navigate {url:"file:///var/run/secrets/kubernetes.io/serviceaccount/token"}`
+ `Runtime.evaluate {expression:"document.body.innerText"}` (or `Page.printToPDF`)
-> **read the SA token / `/etc/passwd` / `~/.aws/credentials`.** Full payloads and
the `/json/new?file:///...` GET-tab bypass in `references/headless-chrome-cdp.md`.

**Chain 2 — Next.js RSC -> `execSync('id')` (CVE-2025-55182).** Fingerprint;
safe step 1 (`Next-Action:` 40 chars text/plain -> `404 Server action not found`);
safe step 2 (same header, multipart body -> `500` with RSC `{"a":"$@1",...}` =
deser-before-validation is live); then the prototype-pollution gadget whose
`_response._prefix` runs `process.mainModule.require('child_process').execSync('id')`
and reflects the output in the `1:E{"digest":"<output>"}` field. Be first — it's
mass-exploited. `references/nextjs-rsc-rce.md`.

**Chain 3 — SSRF -> IMDS -> IAM creds -> code-push.** SSRF to
`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
(IMDSv2: `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`
first, then send `X-aws-ec2-metadata-token`). `aws sts get-caller-identity` is the
proof; read-only enum of S3/CodeCommit/ECR/Lambda scopes states the code-push ->
deploy-RCE impact by inference. The actual push is rung 5 — not attempted: d0x's approval before execution. Hand the
IAM half to `cloud-exploitation`. `references/ssrf-to-rce.md`.
(`aws` CLI absent; **`boto3` (1.43.18) is installed and signs SigV4** — use `python3 -c "import boto3;..."`; before the proof
step; the metadata reads themselves are plain HTTP and need nothing.)

**Chain 4 — file write -> loaded path -> RCE.** A write primitive (Perforce with
unset `P4CLIENTPATH`, Zip-Slip, path-traversal upload) becomes RCE when the path is
*loaded*: webshell in webroot, `~/.ssh/authorized_keys`, `/etc/cron.d/x`, a DLL on
the Windows search path, a `.pth` in site-packages, a git `hooks/post-checkout`.
Prove the write on a sentinel path first; land `id` only through a benign owned
loaded path (your own tenant webroot). `references/file-write-to-rce.md`.

## Algorithm

1. **Map the execution candidate.** Feature, input, parser/tool + **exact version**,
   intermediate storage, worker, sink, privilege, container/k8s?, sync vs async.
   Fingerprint versions from headers, error text, rendered UA, `/json/version`.
2. **Classify the surface** (§0 / trigger map) and load the one reference. One
   boundary = one class; go DEEP before widening.
3. **Confirm the oracle** — a body/behaviour differential, not just a status code:
   `HeadlessChrome` UA in the render, `404 Server action not found`, `49` reflected,
   an SDK/parser error naming the engine, a `/json` list, a metadata read echoing a
   file. Prove input reaches the sink before firing the exploit.
4. **Fire the benign command on prod (rung 1).** `id`/`whoami`/`hostname`, or read
   `/etc/passwd` / the SA token / `/proc/self/environ`. Read the output back. That
   is the finding. If the payload is genuinely destructive-only (DoS CVE, parser
   bomb, real-path write), drop to UAT (rung 4) or source+local repro and say so.
5. **Capture execution context.** uid, hostname, container vs node, k8s namespace,
   reachable services, attached IAM role/SA. State blast radius (one pod? cluster?
   all tenants?).
6. **Escalate only as far as needed, then STOP.** Don't take a reverse shell to
   "prove it harder." A benign command + context is a complete Critical.
7. **Validate + write it down.** High/Critical -> `validation` re-proves; then
   write it to `targets/<program>/leads/` in the format in
   `../_shared/references/output-contract.md` and rotate to the next boundary.
   Never close the target.

## Confirmation oracles

**Strong (this is a finding):**
- `id`/`whoami`/`hostname`/`uname` output reflected in the response, PDF, log, or
  OOB callback;
- a controlled marker file **you** wrote appears / is read back;
- `/etc/passwd`, the k8s SA token, `/proc/self/environ`, or app source read back via
  the chain;
- Next.js step-2 returns `500` + an RSC `{"a":"$@1",...}` body, then the gadget
  reflects `id` in `1:E{"digest":...}`;
- an OOB DNS/HTTP hit whose subdomain/path carries `$(whoami)` output.

**Weak (keep hunting, not yet a finding):**
- `{{7*7}}` -> `49` with no engine-specific `id` proof (could be a sandboxed engine);
- payload string reflected without evaluation;
- old version fingerprinted but the vulnerable code path is unreachable;
- an upload accepted but never processed server-side;
- timing variance with no repeatable baseline.

**Not a finding:**
- client-side JS execution only (that's XSS, not RCE);
- a version banner alone (CVE fingerprint with no fired proof) — downgrade to a
  chain candidate;
- SSRF hitting IMDS where the IAM role has no useful permission;
- a file write to a path that is never loaded at runtime;
- SSTI in a sandboxed engine with no demonstrated escape.

## Converts? (severity — grade honestly, do not inflate)

- **Critical:** unauth/pre-auth RCE with a fired benign command (Next.js RSC
  `execSync`, unauth converter RCE); headless-Chrome CDP reading the k8s SA token or
  cloud creds (cluster/tenant blast radius); SSRF -> IMDS -> over-permissioned IAM
  -> demonstrable code-push path; command injection returning `uid=0(root)`.
- **High:** authenticated / low-priv RCE bounded to a worker/converter/tenant
  workspace with a fired command; file-write proven on a real loaded path with a
  benign owned-webroot `id`.
- **Medium:** file write to a non-loaded path; SSTI with reflected `49` but a
  sandbox you couldn't escape; IMDS reachable but role is useless; a converter CVE
  proven only as file-read of a non-sensitive path.
- **Low / not new:** version-fingerprint-only CVE claim; Next.js RSC on a
  mass-exploited target where you're not first (novelty-check your submitted corpus). A reachable
  sink with no fired command is **not** a High — either land the command or grade it
  for the reach you actually proved.

## Non-destructive rules (the safe ladder in practice)

- **The benign command IS the proof.** `id`/`whoami`/`hostname`/`uname`, read
  `/etc/passwd`/SA-token/`/proc/self/environ`. Non-mutating -> rung 1 -> fire it on
  prod. Do NOT default to "local/staging repro"; that's the fallback for
  destructive-only payloads.
- **No reverse shells, no persistence, no destructive commands** (`rm`, `kill`,
  writing real loaded paths, `mkfs`, dropping crons on prod). No credential *use*
  beyond the read that proves the read — harvested creds go to `cloud-exploitation`
  read-only (`sts get-caller-identity`), then STOP: anything further requires d0x's approval before execution.
- **Own/anon context for any write.** Marker files to a `__poc_<rand>__` path you
  own; converter payloads read a benign file (`/etc/passwd`) not another tenant's
  data; revert anything you change immediately.
- **Minimal:** one command, one file, one representative record. State scale by
  inference — never dump the filesystem or mass-read PII "to show scale."
- **Scope is a safety boundary, not a hunting filter.** Only the **dial target** is
  gated — the renderer host, the Next.js host, the upload endpoint, the SSRF sink's
  host must be one the program authorized. Payload *values* are never scoped: a
  `file:///etc/passwd` URL, `169.254.169.254` in an SSRF param, `localhost:9222`
  reached from **inside** an authorized renderer, a benign command string. If a host
  is genuinely out of scope, pivot surface — and if the sink is in scope but the
  payoff would dial a host that is not, surface the chain instead of dialing it.
- **NEVER fire a DoS-shaped payload on prod** — the Next.js RSC circular-reference
  DoS, parser bombs, zip bombs, ReDoS. Report those on version+reachability, or
  prove on UAT.
- **UAT for anything intrusive** if RoE restricts it (`*-uat`/`*-oat`); on prod stop
  at the rung-1 benign read and state prod-equivalent impact.
- **Flag every credential/token you read for rotation** in the report (SA token,
  IAM creds, `.env` secrets).
- **Nothing will stop you.** The rung is decided before the request is built, by
  reading the ladder — no guard fires afterwards to tell you a line was crossed.
  When a step would be rung-3-on-prod / other-user-data / a write, drop to the
  safe-ladder equivalent (benign read on prod, or full proof on UAT) yourself; if
  neither reaches it, send the exact request and rollback plan to the primary
  agent so it can ask d0x directly. Continue independent safe angles.
- High/Critical claims, any fired command, any callback -> `validation`
  before `report-writing`.

## Evidence policy — what to capture, what to redact

Raw proof (fired-command output, decoded SA/IAM tokens, the `/json`
`webSocketDebuggerUrl`, rendered PDFs/screenshots) goes under
`targets/<program>/notes/` while it is raw, and moves to
`targets/<program>/findings/` once it is a proven bug. Redact victim PII; keep
uid, hostname, pod/container ids, namespace, role ARN, and tool versions — those
are the impact.

Capture all of these before writing the lead:

- exact source input and sink — endpoint / param / field / tool + **version**;
- **the benign command fired and its output** (`id`/`whoami`/`hostname`/`uname -a`)
  or the file read back (`/etc/passwd`, the k8s SA token, `/proc/self/environ`).
  This is the finding; a reachable sink with no fired command is not a High;
- the oracle differential proving reachability — `HeadlessChrome/<ver>` in the
  render, `404 Server action not found`, the `500`+RSC body, a reflected `49`, a
  `/json` target list, a metadata read echoing a file;
- execution context: uid, host/pod, container vs node, k8s namespace, attached IAM
  role / service account, reachable internal services — and the blast radius stated
  (one pod / the cluster / all tenants);
- the negative control: benign input renders normally, a sanitised sibling param
  does not fire, an external URL works while `file://`/`localhost` is blocked;
- an explicit statement of what was NOT done — no reverse shell, no persistence, no
  destructive command, no filesystem sweep, no other-tenant data, no DoS payload;
- rotation flags for every credential/token/secret read (SA token, IAM creds,
  `.env` values);
- the `validation` verdict for every High/Critical claim.

Title the lead specifically and keep the string STABLE across sessions (the dedup
key is `primitive|host|claim`): name the class + sink — `Next.js RSC execSync`,
`headless-Chrome CDP SA-token read` — never "possible RCE".

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- SSRF needed to reach IMDS/internal admin first -> `ssrf-safe`; then §Chain 3 here.
- Harvested IAM creds / k8s SA token / cloud markers -> `cloud-exploitation`
  (drives them to impact read-only).
- A raw key/secret surfaced by the chain (Braze, Stripe, `AIza`, dotCMS) ->
  `exposed-secrets` (after checking
  `../_shared/references/public-by-default-keys.md`).
- **Object deserialization is the actual primitive** — a `rO0`/`aced0005`/`/wE`/
  `O:`/`gA[JNSW]` (pickle, any of proto 2-5)/`BAh` blob, a `@type`/`$type` mapper,
  a leaked signing key — ->
  `deserialization-hunting`, which owns the gadget selection and the leaked-key
  forge ladder for every runtime. This skill keeps the command/template/upload/
  write sinks. Next.js RSC is the one both share, via
  `../_shared/references/nextjs-rsc-deser.md`.
- RCE requires a role/tenant bypass first -> `idor-bola` / `auth-flow-bypass`,
  then back.
- Confirmed bug -> `validation` -> `report-writing`.
