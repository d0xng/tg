# Case Patterns — generalized SSRF technique catalog

Recognition patterns, not detectors: seeing the shape means "probe this class here,"
never "it's vulnerable." Reflection > blind; caller-token-forwarding and IMDS
reachability are the escalators that lift SSRF from Medium to High. Each entry gives the
feature TYPE to recognize, the param/schema shape, the bypass, the oracle ladder, and a
neutral "converts to <sev> when <condition>" verdict — match your live target to the
closest shape and replay.

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Contents

- AI URL-fetch SSRF — meta-pattern (high recurrence)
- Split-URL arguments — there is no URL to filter (GraphQL and RPC APIs)
- `userinfo@` allowlist bypass
- IP-literal / wildcard-DNS bypass
- Second forgotten URL param (proxy-style)
- Webhook register-then-test port oracle
- URL-taking tool that forwards the caller's token (MCP-style) — HIGH
- IMDS / internal-pod reach + body reflection — ESCALATOR
- Meta-lesson

---

## AI URL-fetch SSRF — meta-pattern (high recurrence)

**Recognize it**: any AI/ML feature that takes a user-supplied URL for "analysis /
similarity / describe / edit / inpaint / multimodal chat" and fetches it server-side
**before** validating it is really an image/asset. The URL lives in a structured input
field, not a top-level `url=` param, which is why filters miss it.

Param/schema shapes to hit (these are model/schema-level, the same across deployments):
`attachments[].url`, `image_url.url` (OpenAI `messages[].content[].type:image_url`),
`search_parameters[similar_url]`, `inputs.href` + `storage:"external"`,
`inputs.<img>.repo:path` + `repoType:"HTTP"`, `presignedUrl`. Callback UAs seen on the
internal fetcher: `node`, `Go-http-client`, `python-requests`, `libcurl`, plus opaque
internal-service UAs (e.g. `CPF`, `IPS/1.0`, `Imagecore Service`). The `x-api-key` /
`X-Api-Key` these features want is usually a **public client_id** baked into the web app
(free-tier, resolve it against `../../_shared/references/public-by-default-keys.md`) — that
is not the finding, the SSRF is.

Generalized variants, keyed by the FEATURE TYPE (recognize the type, find its own
route/param in the target's JS/API — do not expect a fixed path):

- **Multimodal chat "continue conversation" with attachments** — the request carries an
  attachment list (`attachments:[{type:image_url,url:...}]`); the fetched result is
  reflected back inside the assistant/tool-result content. Reflected -> readable.
  Bypass that lands: `userinfo@` (`https://<allowed-host>@<attacker-host>/<uuid>/TAG`).
- **Media / "find similar" search by URL** — a search endpoint takes a
  `similar_url`/`image_url` query and fetches it. Bypass that lands: wildcard-DNS
  (`http://<dashed-public-ip>.sslip.io/x.png`) when raw IPs are blocked but hostnames
  resolve.
- **OpenAI-schema chat completions** — the OpenAI `messages[].content[].type:image_url`
  `image_url.url` field is fetched; the response/headers leak
  `X-Envoy-Peer-Metadata-Id` (Istio/Envoy mesh fingerprint); **timing oracle** ~1s for
  an open port vs ~11s (connect-timeout) for a closed one.
- **ML predict / inference with an async status endpoint** — the predict/inference call
  accepts an input URL (`inputs.<x>.repo:path` + `repoType:"HTTP"`) and returns a job
  id; a **separate async status/result endpoint keyed by that id reflects the FULL
  fetched body**. That reflected-read sink is the top converter — hunt the status/job
  endpoint, not just the predict call. When the allowlist carries an
  `*.s3.amazonaws.com` wildcard, an attacker-owned S3 bucket is accepted as "trusted".
- **Image-edit / enhance ("autoTone"-style)** — takes `inputs.href` + `storage:external`
  and PUTs the output to an attacker-controlled `outputs[].href`; blind, so read it with
  the **libcurl error-string oracle** (`Connection refused` vs `Connection timed out` vs
  an HTTP-parse error = got a response).

**Replay**: 1) enumerate every URL field in the feature's JS/API. 2) OOB-confirm + capture
the egress IP and any leaked trace headers. 3) if blocked -> `userinfo@` / `sslip.io` /
decimal IP / open-redirector. 4) probe `169.254.169.254`, `127.0.0.1`, internal stage
hosts; time open vs closed. 5) find the reflection sink (async status/job endpoint,
error body, preview render); else fall back to timing/error oracle. 6) check the
allowlist for `*.s3` wildcards. **Converts?**: the fetch is typically accepted; the
async-status **full-body-reflection** variant converts highest (High) — prioritize
finding any body-leak sink over proving a bare blind fetch.

## Split-URL arguments — there is no URL to filter (GraphQL and RPC APIs)

A sink that takes the URL as **separate typed arguments** rather than one string:

```graphql
mutation { importPaste(scheme: "http", host: "169.254.169.254", port: 80, path: "/latest/meta-data/") { result } }
```

The server assembles it. No URL exists on the wire, so URL allowlists, URL parsers
and WAF rules matching on a URL have nothing to match, and the whole bypass ladder
is unnecessary — `host` takes an internal name directly. `port` being a first-class
integer argument makes port scanning one request per port (batch them where the API
allows it), which is the cheapest internal map available.

Blind oracle: a closed port returns an empty result immediately; an open port that
never replies leaves the request pending to timeout. Time it, do not read it.

Recognise the shape by the argument set — `scheme`/`host`/`port`/`path`, or
`protocol`/`hostname`/`endpoint` — not by the word "url".
`../../graphql/references/injection-forgery.md` §SSRF for the GraphQL specifics.

## `userinfo@` allowlist bypass

**Recognize it**: an SSRF host allowlist that does substring/prefix matching — "host not
allowed" appears only when the allowed string is absent from the URL. **Technique**:
`https://<allowed-host>@<attacker-host>/<path>` — the check sees the allowed substring;
the HTTP client connects to the authority *after* the `@`. (Go's `net/http` converts
userinfo into an `Authorization: Basic` header, so the credential can leak outbound to
your host too.) **Converts?**: reliable as the bypass primitive inside a chain; it is the
first bypass to try on any "host not allowed". Rate the chain by what it reaches, not the
bypass alone.

## IP-literal / wildcard-DNS bypass

**Recognize it**: the filter blocks the `127.0.0.1` / `169.254.169.254` literal but never
canonicalizes, or it rejects raw IPs but resolves and fetches any hostname.
**Technique**: rotate encodings the guard didn't normalize — decimal `2130706433`, octal
`0177.0.0.1`, hex `0x7f000001`, short `127.1`, `0.0.0.0`, IPv6-mapped `[::ffff:7f00:1]`;
or wrap the target IP in wildcard DNS (`<dashed-ip>.sslip.io`, `nip.io`). **Oracle to
pair with it**: an image-proxy that returns `Media could not be read` on an open port vs
`Access Denied` on a closed one is a port oracle even when the body isn't reflected.
**Converts?**: informative standalone (recon-only) — use it as the bypass primitive
inside a bigger chain (reflection / cloud-cred reach), and rate that.

## Second forgotten URL param (proxy-style)

**Recognize it**: an endpoint with two URL-ish params where only one is hardened and the
other is forgotten — recognizable name pairs like `address`+`proxyaddress`, `url`+`proxy`,
`target`+`via`, `src`+`fallback`. **Technique**: the forgotten param often flows straight
into `curl_easy_setopt(CURLOPT_PROXY)` (or an unvalidated fetch); point it at the internal
target and read the leaked banner. **Oracle**: the internal service banner appears inside
a `500 Connection timed out ... <banner>` error body. Always test *every* URL-ish param
separately, not just the obvious one. **Converts?**: informational on emulated/firmware
surfaces; converts on a live service where the reached internal target has value.

## Webhook register-then-test port oracle

**Recognize it**: the app lets you register a webhook/callback URL with no validation on
create, then offers a "test"/"send test event" action that fires it server-side.
**Technique**: register `http://localhost:<port>/` (or an internal host), trigger the
test, and read the internal state from the error/response differential. **Oracle
ladder**: an HTTP-status-ish error (`invalid status code 403`) = reached an open service;
a generic error (`general_exception`) = closed; a success (`received successfully` / 2xx)
= reached a 2xx service. Build the truth table from one known-open and one known-closed
probe, then walk `127.0.0.1:<port>` / internal ranges. OOB-confirm the origin first.
**Converts?**: Medium standalone (blind port oracle); pair with IMDS reachability or a
reflected read for High.

## URL-taking tool that forwards the caller's token (MCP-style) — HIGH

**Recognize it**: a server-side tool/integration that takes a URL and fetches it while
**attaching the caller's own auth to the outbound request**. MCP servers are the canonical
shape — JSON-RPC 2.0 over streamable HTTP, often `X-Powered-By: Express`, with a
URL-taking tool (field names like `authorUrl` / `importUrl` / `webhookUrl`) and sometimes
a public, unauthenticated registry that leaks every server URL + tool schema.
**Technique**: the tool fetches the URL server-side AND forwards the caller's
`Authorization: Bearer` (or session cookie / internal service token) -> point it at your
OOB host and the listener **receives the victim's token** (account takeover /
cross-service access). Also reachable via indirect prompt injection when an agent drives
the tool.

**Replay** (protocol-level, the same for any MCP server — these method names are the MCP
spec, keep them): 1) if a registry exists and is unauth, pull the server list + tool
schemas from it. 2) `initialize` -> capture the `mcp-session-id`; `tools/list`. 3) find
the URL-taking tool. 4) `tools/call` it with your OOB URL as the URL arg; inspect the
captured request for an `Authorization` / `Cookie` / `X-Api-Key` / `X-Amz-Security-Token`
header. 5) confirm any body reflection and probe IMDS (`169.254.169.254/latest`) from the
same primitive. **Converts?**: typically High when the outbound forwards the caller's
token (decode it: scopes, `exp`, `aud` — a broad/write scope raises severity). Always
check whether the outbound carries caller auth — that single question is what turns this
from Medium to High.

## IMDS / internal-pod reach + body reflection — ESCALATOR

**Recognize it**: any confirmed SSRF on AWS/Azure/AKS/EKS/GKE where error bodies are
reflected, or where trace headers (`traceparent`, `uber-trace-id`,
`X-Envoy-Peer-Metadata-Id`, `x-datadog-*`) leak to your OOB. **Technique**: probe the
cloud metadata service + in-pod loopback (all universal, full detail in
`cloud-metadata.md`) — Azure
`169.254.169.254/metadata/instance?api-version=2021-02-01` (`Metadata:true`),
`/metadata/identity/oauth2/token`; AWS
`169.254.169.254/latest/meta-data/iam/security-credentials/` (IMDSv2's PUT-token blocks
bare GETs); GCP `metadata.google.internal/computeMetadata/v1/...` (`Metadata-Flavor:
Google`). `127.0.0.1` hitting the same app frequently bypasses the auth-enforcing ingress
-> internal/admin routes. **Oracles**: a `500` on `127.0.0.1/<internal-route>` = the same
app answering on loopback (vs a connection error when closed); a CRLF
`%0d%0aMetadata:true` returning `Request blocked by AAD Pod Identity NMI` fingerprints
AKS pod-identity. Recognize the sink type in the wild by its behavior — a
workflow/automation action that writes or echoes fetched content is a common host for
this (it reflected Azure IMDS bodies + loopback routes). **Converts?**: reflection + IMDS
reach typically lifts SSRF to High; blind-only stays Medium. Report the reachability even
when cred-extraction is blocked by IMDSv2 — reaching the metadata network is itself the
proof.

---

## Meta-lesson

The two moves that lift a Medium blind SSRF to High/Critical are **finding the reflection
sink** (a status/job/tool-result endpoint that returns the fetched body) and **checking
whether the outbound carries the caller's token**. Ask both on every confirmed sink.
Never close a sink at "the server fetched" — chase reflection and token-forward first,
then metadata reach.
