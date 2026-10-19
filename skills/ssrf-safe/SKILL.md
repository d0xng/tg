---
name: ssrf-safe
description: "Hunt and safely validate SSRF in server-side URL or host fetchers, webhooks, previews, imports, renderers, image proxies, feeds, identity metadata, XML/SVG processing, and AI or MCP tools. Use when attacker-controlled URL components reach a backend request, an OOB callback indicates server fetch, or internal and cloud metadata access may be possible. Ask d0x for the webhook or OOB endpoint before payloads and never write to internal services."
---

# SSRF — find the fetch, point it inward, reach the metadata, escalate

SSRF = you control where the server makes a request. Blind/recon-only SSRF is often
Medium and programs deprioritize it. **The money is in reaching cloud metadata,
internal-only services, loopback admin routes, reflected response reads, or making
the outbound request carry the caller's auth token.** Reaching `169.254.169.254`,
reading an IAM credential, or exfiltrating a forwarded `Authorization` header IS the
finding — it is the proof the program pays for, never a gray zone to pause on.

This skill recalibrates every "keep it passive" instinct to the shared ladder in
`../_shared/references/safe-ladder.md`: read-only first (hit your own OOB listener,
read the metadata/reflection you are authorized to reach) → own/anonymous context →
minimal proof → UAT for anything risky → reach the payable impact. **Do not stop at
discovery.** A confirmed sink that you did not point at metadata/internal is an
unfinished finding.

The proven SSRF technique patterns (AI image-fetch, decimal-IP bypass, webhook
port-oracle, MCP caller-token exfil, IMDS reflection) are worked out in
`references/case-patterns.md` — read them alongside this; this file is the broad
methodology, that file is the generalized patterns with exact endpoint/param shapes.

Every command below runs in a normal shell on this laptop — `curl`, `dig`,
`interactsh-client`, `python3` are executed, not described.

## Read-on-demand references

Load the one that matches the phase you are in:

- `references/bypass-ladder.md` — the full ordered ladder when the URL is filtered:
  `userinfo@`, decimal/octal/hex/short IP encodings, IPv6-mapped
  `[::ffff:169.254.169.254]`, `sslip.io`/`nip.io` wildcard DNS, second forgotten
  param (`proxyaddress`), open-redirect chain to `169.254.169.254`, URL-parser
  confusion, DNS rebinding, and `gopher://`/`dict://`/`file://` scheme smuggling.
- `references/cloud-metadata.md` — reach + read: AWS IMDSv1 AND IMDSv2
  (token-then-creds), Azure IMDS `Metadata:true` + OAuth2 token, GCP
  `Metadata-Flavor: Google` + service-account token, DigitalOcean/Alibaba/Oracle,
  Kubernetes/in-pod loopback, and what to do with each harvested credential. **This
  file is the pack's single owner of the IMDS/metadata endpoint catalog.**
- `references/oob-and-oracles.md` — interactsh OOB confirmation (DNS+HTTP+SMTP),
  egress-IP + leaked-trace-header fingerprinting, and blind oracles (timing,
  status/error differential, response-length) for port scanning without reflection.
- `references/escalation.md` — turning reach into High/Critical: caller-token
  forwarding, reflected-body sinks, the AI `image_url` fetch vector, IMDS-creds →
  assume-role, gopher → Redis/internal, and applying the PURSUE/SKIP key table.
- `references/cve-tooling.md` — CVE-2026-44578 (Next.js WebSocket-upgrade SSRF) built
  by hand with raw sockets, plus classic stack-specific SSRF CVEs to fingerprint.
- `references/case-patterns.md` — generalized technique patterns with exact payloads.
- `references/plays.md` — the eight plays as they actually ran in **d0x's own 16 reports of this class**, with the outcome of each: which bypass was needed (usually none), which oracle confirmed it, and the exact line that separates a Medium from an informative. Read it before deciding how far to push a sink.
- `references/case-index.md` — those 16 by play, host, severity and state, with corpus paths and the saturated-host list. Read it at DEDUP: eleven of the sixteen are one estate.
- `../_shared/references/output-contract.md` — where results go: the notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim` dedup key, and the severity enum.
- `../_shared/references/tooling.md` — what is installed on this host, what is not, and the install line for each missing binary.

## 1. Find the sink — anywhere the server fetches a URL/host

Mine the JS + API for params the backend will request. Obvious names: `url`, `uri`,
`link`, `src`, `image_url`, `imageUrl`, `avatar`, `logo`, `icon`, `callback`,
`webhook`, `redirect_uri`, `dest`, `target`, `feed`, `rss`, `endpoint`, `host`,
`domain`, `proxy`, `proxyaddress`, `next`, `continue`, `data`, `path`, `file`,
`document`, `source`, `import`, `fetch`, `href`, `similar_url`, `presignedUrl`.

Features that fetch under the hood: webhook test/registration, URL preview/unfurl
(chat/social), import-from-URL, "fetch metadata from website", avatar/logo by URL,
PDF/HTML/screenshot generators (headless Chrome), file-upload **by URL**, RSS/feed
readers, image proxies/resizers, OIDC/OAuth discovery
(`/.well-known/openid-configuration`), JWKS URL, SAML metadata /
`AssertionConsumerServiceURL`, XML/SVG parsers (XXE → SSRF), GraphQL `@stream`/url
args, and AI/ML tools taking `image_url`/`similar_url`/`href`+`storage:external`/
`repo:path`. Headers too: `X-Forwarded-For`, `X-Forwarded-Host`, `Referer`, `Host`,
`CF-Connecting-IP` in stacks that route on them.

## 2. Confirm — OOB first, always (self-serve the collaborator)

Confirm the server actually fetches before you spend effort on bypasses. Default =
local `interactsh-client` (`~/go/bin/interactsh-client`) because it captures **DNS +
HTTP + SMTP**, so it handles blind/DNS-only SSRF that HTTP-only listeners miss:

```bash
interactsh-client -json -o /tmp/interactsh.log &   # prints payload domain like cXXXX.<oast-domain>
# → use http://<payload>.<oast-domain>/UNIQ as the SSRF target; tail /tmp/interactsh.log for hits
```

A **DNS** hit alone proves the resolver reached out (even if HTTP egress is blocked).
Fire the confirming request through d0x's **Caido** so the PoC is recorded for
replay/screenshots. If a callback does not land, re-fire it through the proxy before
concluding the target blocks egress — local egress filtering looks identical to a
non-vulnerable sink. Full oracle detail (egress fingerprint, blind timing/error
oracles) is in `references/oob-and-oracles.md`.

## 3. Bypass the filter — the ladder

If the raw URL is rejected ("host not allowed" / SSRF-protection error), walk
`references/bypass-ladder.md` in order. Each rung defeats a specific filter style —
`userinfo@` for substring allowlists, decimal/octal/hex/IPv6-mapped literals for
denylists, `sslip.io`/`nip.io` for raw-IP blocks, the forgotten second param, an
open-redirect chain to `169.254.169.254`, parser confusion, DNS rebinding, and
`gopher`/`dict`/`file` when the scheme filter is weak. Do not abandon a confirmed
sink because the first raw payload was blocked — that is the same-angle trap; rotate
through the ladder.

## 4. Reach cloud metadata + internal targets — this is the escalation

Once you can hit internal, this is where SSRF becomes payable. Point it at the
metadata service and the loopback app per `references/cloud-metadata.md`:

- **AWS**: IMDSv1 `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  → role → creds. IMDSv2 = a `PUT /latest/api/token` then the creds request with the
  token header — reachable when the SSRF lets you set method+headers (gopher, or a
  full-request primitive like CVE-2026-44578). `/latest/user-data` often holds
  secrets/bootstrap scripts.
- **Azure**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  requires header `Metadata:true`; `/metadata/identity/oauth2/token?resource=...` →
  bearer for Graph/ARM. If you cannot set headers, try CRLF `%0d%0aMetadata:true`.
- **GCP**: `http://metadata.google.internal/computeMetadata/v1/` requires
  `Metadata-Flavor: Google`; `/instance/service-accounts/default/token`.
- **In-pod loopback**: `127.0.0.1:<port>` frequently bypasses the auth-enforcing
  ingress → the app's own internal/admin routes, plus siblings (Redis 6379, Elastic
  9200, actuator/metrics, internal admin APIs).

Read the credential/metadata to **prove access** — that read is the deliverable and
the lowest safe-ladder rung that proves the class. See `references/escalation.md` for
what to do with each harvested credential and how far to climb.

## 5. Blind SSRF — oracles when there is no reflection

No reflected body does not mean no finding. Use the oracles in
`references/oob-and-oracles.md`: DNS-only callback (reach even with HTTP blocked),
timing (open port fast vs closed hangs to timeout), status/error differential (`Media
could not be read` vs `Access Denied`; `invalid status code 403` vs
`general_exception`; libcurl error strings), and response-length differential. Build a
port scan over `127.0.0.1:<port>` and internal ranges from these signals.

## 6. Escalate — reflection > blind, token-forward > reflection

Per `references/escalation.md`:
- **Reflection**: if the tool result / error / status endpoint returns the fetched
  body, you can READ internal responses — chase that sink relentlessly (full-body
  reflection at an async status endpoint is the top-converting reflected-read sink).
- **Caller-token forwarding**: does the outbound request carry the caller's
  `Authorization: Bearer`? If yes, point it at your host and **exfil the victim's
  token** — this is the High/Critical lifter (the MCP caller-token-exfil pattern).
- **IMDS creds** → assume the cloud role → S3/internal API. **Internal
  Redis/Elastic/admin** → data or RCE via gopher.

Always report the concrete internal thing you reached (which metadata field, which
loopback route, which forwarded token), never "the server made a request."

### What 16 of d0x's own reports in this class actually returned

Full write-ups in `references/plays.md`; the index in `references/case-index.md`.
The distribution is the calibration: **11 Medium, 4 High, no Criticals.**

**The line between Medium and informative is whether a named internal resource came
back.** All four informative results are oracle-only or refusal-only — a port scan, a
status differential, a proxy error page. Every one proved the fetch happened; none
brought back an internal document. Learn one real internal hostname before writing up.

**Reaching IMDS is not credential theft.** Two reports reached it; one got `200` on
the IAM credentials path through a blind oracle and stated plainly that the role name
was not extractable that way, then described the chain that would be needed. Both were
triaged *because* they named the remaining barrier instead of implying it was gone.

**The one non-duplicate High leaked a credential** — an MCP tool that attached the
caller's own bearer to the outbound request. Token-forwarding is the lifter; keep
checking for it on every sink before settling for the oracle.

**Most sinks needed no bypass at all.** Five of the sixteen had no host validation
whatsoever. Fire the plain internal literal before climbing the ladder.

**On a crowded estate, pre-empt the duplicate closure.** Three reports list the sibling
SSRF reports they are *not* duplicating and name the difference — different service,
runtime, egress region, root cause. Eleven of these sixteen are one estate; that
paragraph is what separated triaged from duplicate.

## 7. CVE-specific tooling

`references/cve-tooling.md` covers **CVE-2026-44578** (Next.js WebSocket-upgrade
SSRF, versions 13.4.13–15.5.15 / 16.0.0–16.2.4) — a full-request primitive that
reaches IMDS in-band and does the IMDSv2 PUT-token dance a bare `?url=` sink cannot.
Build it by hand (`curl --http1.1` with the upgrade headers, or a short `python3`
raw-socket script), and confirm out-of-band; the ALB fixed-response false positive is
covered there. Plus classic SSRF CVEs to fingerprint by stack (ImageMagick,
wkhtmltopdf, Spring Cloud Gateway, Confluence/Jira webhooks).

## Non-destructive posture (recalibrated — reach, don't wreck)

Reaching metadata and reading a credential is **read-only and on the safe ladder** —
do it. The boundaries are about *destruction*, not *reach*:

- **Scope is a safety boundary, not a hunting filter.** Dial only hosts the program
  authorized; a victim id, a foreign org id, or an internal host inside the
  path/query/body/header is always allowed — only the connection target is gated. Your
  own OOB collaborator is your infrastructure and is always a legal exfil destination.
  If a host is genuinely out of scope, pivot surface.
- Fire OOB only to your **own** collaborator; use **your own / anonymous** context for
  the sink where possible (`../_shared/references/safe-ladder.md` rungs 1–2).
- Harvested IAM/cloud creds: prove they are live and over-privileged with the cheapest
  read — `aws sts get-caller-identity` (**the `aws` CLI is absent, but `boto3` is importable and does the SigV4 signing that
  `curl` cannot — `python3 -c "import boto3;print(boto3.client('sts').get_caller_identity())"`**), or for
  Azure/GCP decode the returned JWT and read `aud`/`roles`/`scp`, which needs nothing
  but `jq`. Do NOT pivot-enumerate
  the whole account or dump other users' PII to "show scale" — scale is stated by
  inference (rung 3). Full pivoting → `cloud-exploitation` skill — anything beyond the reach itself requires d0x's approval before execution.
- Do NOT write to internal services (no gopher-Redis `SET`/`FLUSHALL`, no state change)
  on real infra — prove the reach, not the destruction (rung 5 = ask d0x directly before executing).
- If the program restricts privacy/degradation testing to UAT/OAT, do the deeper proofs
  on `*-uat`/`*-oat` and state the prod-equivalent impact by inference (rung 4).
- If a SSRF-reached read leaks a client-side key, resolve it against
  `../_shared/references/public-by-default-keys.md` before reporting — a Sentry DSN /
  Maps key is SKIP; an IMDS IAM cred / Azure token / server secret is the finding.

## Evidence to capture (per confirmed sink)

Write it to `targets/<program>/notes/` as you go and promote per
`../_shared/references/output-contract.md`. A lead that does not state the **concrete
internal reach** ("the server made a request") is not a finding.

- **Sink**: exact host, endpoint, method, param name, request body shape.
- **OOB proof**: the interactsh payload domain and the DNS/HTTP hit with its source
  IP — or the status/error-string oracle that stands in for reflection.
- **Egress fingerprint**: egress IP + ASN (which cloud?), leaked trace headers
  (`X-Envoy-Peer-Metadata-Id`, `x-datadog-*`, `traceparent`, `X-Amzn-Trace-Id`),
  outbound User-Agent.
- **Bypass**: which ladder rung defeated the filter, with the exact payload
  (`userinfo@`, decimal `2130706433`, `169-254-169-254.sslip.io`, second param, CRLF,
  gopher, redirector).
- **Internal reach**: the concrete thing reached — the metadata field read
  (`iam/security-credentials/<role>` returned creds), the loopback route
  (`127.0.0.1/<admin>` = 500, same app answering), the internal port mapped by the
  oracle, or the forwarded `Authorization` token (decoded scopes/`exp`/`aud`).
- **Reflected vs blind**: where the body surfaces, or the oracle truth table
  (error-string / timing / status per port state).
- **Escalation reached**: caller-token exfil, reflected internal read, IMDS creds
  proven live, or gopher-service reach.
- **Safe-ladder statement**: which rung the proof stopped at and why ("read the IMDS
  role name and confirmed creds returned, rung 1; did not pivot the account").
- **Negative control**: a bogus internal path or a known-closed port showing the
  opposite oracle state — this is what rules out the CVE-2026-44578 ALB
  fixed-response false positive.
- **Redaction**: keep raw OOB logs, captured headers, and full metadata responses in
  `targets/<program>/notes/`; in the lead/finding redact a harvested credential to its
  class plus `exp`/scopes and point at the raw note. Flag every credential for rotation.

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- `cloud-exploitation`: harvested IMDS/Azure/GCP credentials → assume-role / S3 /
  internal API pivot (ask d0x directly before executing, or UAT first).
- `exposed-secrets`: an SSRF-reached read leaks a PURSUE key/secret (resolve it
  against `../_shared/references/public-by-default-keys.md` first).
- `rce-hunting`: gopher → internal service, or a reached admin route, chains to code
  execution. IMDS creds → code-push (CodeCommit/ECR/Lambda/S3 artifact) → RCE is owned
  by `../rce-hunting/references/ssrf-to-rce.md` Step 4.
- `ai-injection`: the fetch sink is an AI tool also reachable via indirect prompt
  injection.
- `validation`: every High/Critical claim (metadata creds, token-forward, reflected
  internal reads) before the report.
- `report-writing`: draft once validated.

Cross-reference `references/case-patterns.md` for the matching proven pattern.
