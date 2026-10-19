# Case patterns — generalized RCE shapes + the oracle that confirms each

A catalog of recognition patterns, not detectors: seeing the shape means "probe
this class," not "it's vulnerable." Each entry is the generalized replay with
placeholders (`<host>`, `<role>`, `<port>`), the oracle that turns it into a
payable finding, and neutral "converts when …" grading. Grade honestly against
the "Converts?" notes.

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Headless Chrome / CDP -> file read -> k8s/cloud creds
- **Shape:** a server-side HTML-to-PDF / screenshot / thumbnail / invoice renderer
  that executes JS in a headless Chromium.
- **Replay:** inject JS into the renderer, reach the localhost DevTools port
  (`9222` or the swept `30000-50000` range), open its `webSocketDebuggerUrl`, and
  drive `Page.navigate file:///…` + `Runtime.evaluate` / `Page.printToPDF` to read
  a `file://` URL — the k8s SA token, `/etc/passwd`, `~/.aws/credentials`.
- **Oracle:** `HeadlessChrome/<ver>` in the render; `/json` returns a
  `webSocketDebuggerUrl`; the file contents appear in the returned PDF/text/OOB.
- **Converts?** Strong. Arbitrary file read from a server-side renderer that reaches
  the SA token / cloud creds typically converts Critical (cluster/tenant blast
  radius). Full chain in `headless-chrome-cdp.md`. Any HTML-to-PDF / screenshot
  feature not already reported is fair game — the *target* is what makes it new.

## Next.js RSC deserialization RCE — CVE-2025-55182
- **Shape:** `x-powered-by: Next.js`, `content-type: text/x-component`, Server
  Actions. Version gate: see the affected table in `../../_shared/references/nextjs-rsc-deser.md` — 19.2.1 is a FIX and Next 16.0.0-16.0.6 IS vulnerable; do not use a single ceiling.
- **Replay:** the safe 2-step probe (`Next-Action` text/plain -> `404 Server action
  not found`, then multipart -> `500`-with-RSC-body = deser-before-validation live),
  then the `child_process.execSync('id')` prototype-pollution gadget whose output
  reflects in `1:E{"digest":"<output>"}`.
- **Oracle:** the `500`+RSC body is the POSITIVE signal (do not bail on it); the
  `digest` field carries the fired command's output.
- **Converts?** Mixed — this is a mass-exploited CVE, so **be first or skip**; value
  is breadth+speed. Sweep the fingerprint across scope, fire the safe 2-step probe
  everywhere, and spend the RCE gadget only where the target's disclosed reports say
  you have a shot. DoS-only (CVE-2025-55184) skews informative/low. Full detail in
  `nextjs-rsc-rce.md`.

## SSRF -> IMDS -> IAM creds -> code-push
- **Shape:** an SSRF sink on a cloud-hosted box.
- **Replay:** point the SSRF at `169.254.169.254` (IMDSv2: `PUT /latest/api/token`
  first) -> `iam/security-credentials/<role>` -> `sts get-caller-identity` +
  read-only scope enum; the code-push (`lambda:UpdateFunctionCode`, ECR push,
  CodeCommit) is stated by inference (rung 5).
- **Oracle:** metadata returns creds; `get-caller-identity` returns a real
  ARN/account; scope enum shows deploy permissions.
- **Converts?** Strong when the role is over-permissioned and reaches a deploy
  surface. The read-only `get-caller-identity` + scope enum is the proof; the actual
  push is stated by inference. `ssrf-to-rce.md`; hand the IAM half to
  `cloud-exploitation`.

## Perforce / file-write -> DLL hijack / loaded-path RCE
- **Shape:** a write primitive — Perforce `client-WriteFile` with unset
  `P4CLIENTPATH` (writes anywhere), Zip-Slip, path-traversal upload, "export to
  path".
- **Replay:** prove the write on a **sentinel path you own**, confirm it lands at an
  arbitrary path, then land `id` only through a benign owned loaded path (a Windows
  DLL earlier in the search order, a webshell in your own tenant's webroot).
- **Oracle:** sentinel file written out-of-workspace and read back; owned webshell
  returns `id`.
- **Converts?** Strong when a loaded path is reachable. `file-write-to-rce.md`.

## SSTI / command-injection / converter CVEs
- **Shape:** `{{7*7}}`/`${7*7}` echoed as `49`; a `cmd`/`host`/`filename` param to a
  tool; an upload processed by ImageMagick/Ghostscript/ExifTool.
- **Replay / CVEs:** ExifTool DjVu Perl-eval (CVE-2021-22204), ImageTragick
  (CVE-2016-3714), Ghostscript `%pipe%` (CVE-2023-36664 / CVE-2018-16509),
  per-engine SSTI gadgets — all public; fire a benign `id`.
- **Oracle:** engine-specific gadget returns `id` output; `/etc/passwd` read back
  from the output image's metadata / rendered PDF.
- **Converts?** Strong when you fire a benign `id`. A version-fingerprint-only claim
  (no fired command) is Low/N-A — see the "Not a finding" gates in each reference.

## Generic dead-ends to note-and-rotate (don't re-walk)
- `{{7*7}} -> 49` with a sandbox you can't escape = Medium reflected-eval, not RCE.
- IMDS reachable but the IAM role has no useful permission = Medium reach-only SSRF.
- Old component banner with the vulnerable code path unreachable = chain candidate,
  not a confirmed RCE.
- File write to a path never loaded at runtime = write primitive, not RCE.
- Client-side JS execution only = XSS, not RCE.

Drop a one-line dead-end note in `notes/` before rotating so future-you doesn't
re-walk a spent angle.
