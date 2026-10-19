# OOB Confirmation + Blind SSRF Oracles

Two jobs: (1) prove the server fetches at all (OOB), and (2) when nothing is reflected
back, extract signal about what internal thing you reached (oracles). No reflected
body does NOT mean no finding — a blind port scan of the internal range plus a DNS-only
metadata reach is still reportable, and the oracle often becomes the read once you
find the right differential.


> **The callback domain is assigned per run, not fixed.** `interactsh-client` picks
> one of `oast.pro / oast.live / oast.site / oast.online / oast.fun / oast.me` at
> startup (five consecutive runs on this host got five different ones). **Copy the
> FULL domain the client prints — never retype the TLD from this file.** A payload
> pointing at the wrong TLD never fires, and a callback that never fires reads as
> "the sink is not vulnerable": a false negative on every SSRF and every blind XSS
> you test that session. Pin it if you prefer determinism: `interactsh-client -s oast.fun`.


## Contents

- OOB — interactsh (self-served, DNS + HTTP + SMTP)
- Fingerprint the egress (do this on every HTTP hit)
- Reflected vs blind — decide the ceiling
- Blind oracles — extract signal without reflection (DNS-only reach; timing differential; status/error-string differential; response-length differential; boolean/HTTP-code differential)
- From oracle to reported reach

---

## OOB — interactsh (self-served, DNS + HTTP + SMTP)

Default collaborator is local `interactsh-client` because it captures DNS **and** HTTP
**and** SMTP — so it confirms blind/DNS-only SSRF where an HTTP-only listener
(webhook.site) would show nothing:

```bash
interactsh-client -json -o /tmp/interactsh.log &     # prints payload domain cXXXX.<oast-domain> at startup
# SSRF target:  http://<payload>.<oast-domain>/UNIQ-<sink-name>
tail -f /tmp/interactsh.log                          # DNS + HTTP hits, with source IP + headers
```

- **DNS hit alone = confirmed** the resolver reached out, even if HTTP egress is
  filtered. That is enough to prove server-side fetch.
- **HTTP hit** additionally gives you the egress IP and any headers the backend
  appended.
- Use a **unique subdomain per sink** (`UNIQ-<sink>`) so you can attribute which
  parameter fired.
- Fallback (HTTP-only, if the interactsh server is unreachable): webhook.site via API
  — `POST https://webhook.site/token` then poll `GET /token/<id>/requests`.
- For the **report PoC**, also fire the confirming request through d0x's **Caido** so
  it is recorded for replay/screenshots.

If a callback does not land, re-fire the request through Caido before concluding the
target blocks egress — local egress filtering and a non-vulnerable sink look identical
from here. Standing up your own collaborator and firing requests at an asset d0x
pointed you at is normal: that is the authorization.

## Fingerprint the egress (do this on every HTTP hit)

- **Egress IP → ASN**: AWS / Azure / GCP / DO range tells you which metadata endpoint
  to probe first (`cloud-metadata.md`).
- **Leaked trace headers** the backend adds and the OOB captures: `traceparent`,
  `uber-trace-id`, `X-Envoy-Peer-Metadata-Id` (Istio/Envoy mesh), `x-datadog-*`
  (Datadog), `X-Amzn-Trace-Id` (AWS ALB). These prove the request originates inside
  the target's infra and fingerprint the platform.
- **Outbound User-Agent** identifies the fetcher: `Go-http-client`, `node`,
  `python-requests`, `libcurl`, `wkhtmltopdf`, headless `Chrome`, plus opaque
  internal-service UAs (e.g. `CPF`, `IPS/1.0`, `Imagecore Service`). The UA hints which
  scheme/parser tricks will work.

## Correlate the callback to YOUR request — a hit is not yet causation

A callback landing on your collaborator proves *something* fetched your URL. It does not
prove **this API call** did, and on a busy estate that gap is where a triager closes the
report. Close it with an identifier that appears on both sides:

- **the unique-subdomain-per-sink rule above is the minimum** — it attributes the hit to a
  parameter, not to a request;
- **stronger: the target hands you the correlator itself.** Many APIs return a request /
  case / trace uuid in their own response body or headers (`{"case":"<uuid>"}`,
  `x-request-id`, `x-amzn-RequestId`), and the backend then propagates that same id onto
  the outbound fetch as `x-request-id` / `traceparent` / `uber-trace-id`. When the id in
  the response you got matches the id in the header your collaborator captured, the chain
  is 1:1 and unarguable.

So: **record the response body/headers of the triggering call, not just the callback.** In
the report, put the two ids side by side. This is the discriminating control for SSRF the
same way a positive control is for authorization — without it you have an observation.

## Did it merely fetch, or did it INGEST? — the two-message discriminator

For any sink that feeds the fetched bytes to a downstream parser (image/ML/document
pipelines), the interesting claim is not "the server fetched my URL" but "**my bytes
reached the parser**". A single feature usually distinguishes the two states in its own
error text:

| What comes back | What it means |
|---|---|
| `DOWNLOAD failed for <input> … : <verbatim upstream body>` | the fetch failed at HTTP level — and the sink handed you the **full upstream response body** as a bonus |
| `Invalid file format or unreadable image` (or any *parser* complaint) | the fetch **succeeded**; the bytes were consumed by the downstream decoder |

Both are wins and they are different wins. The first is a read primitive over every host
the allowlist trusts. The second is attacker-controlled content ingestion — it puts your
bytes into the target's image/document parser, which is the pivot toward a memory-safety
or decompression-bomb argument, and it is the claim worth leading the report with.

Serve a plainly non-image file (a text file) from a host the sink will accept, and the
parser complaint IS the proof of ingestion. Do not send a malformed/bomb file to prove the
next step — that is rung 5.

## The egress proxy's own error page — an unreachable host beats a reachable one

Counter-intuitive but repeatedly productive: point the sink at a host that is **on the
allowlist and not resolvable/reachable** from inside. Instead of an upstream body you get
the *egress proxy's* error page, rendered from inside the perimeter and reflected verbatim:

```
CacheHost: "proxy"
ErrPage: ERR_READ_ERROR
ClientIP: 100.64.5.94                       <- the worker pod's own address
HTTP Request:
  CONNECT  HTTP/1.1
  User-Agent: Apache-HttpClient/4.5.14 (Java/17.0.12)
  Host: <the internal name you asked for>:443
```

Read three things off it: the **worker's own IP** (repeat the request — a rotating
`100.64.0.0/16` CGNAT set means an EKS-style pod fleet, and the spread tells you its
size); the **proxy product** (Squid here, from `CacheHost`/`ErrPage`); and the **runtime
and HTTP-client versions** from the proxied `User-Agent`, which is a far more precise
stack fingerprint than anything the public edge returns.

Internal hostnames that *fail* this way are also confirmation the name exists in the
allowlist — enumerate the `-internal` / `-stage` / `-dev` / regional siblings of any
allowlisted host and record which ones the proxy tried to reach.

**Reaching an S3/GCS/Azure endpoint through the sink turns the storage service's own
error codes into an existence oracle** (`NoSuchBucket` vs `AccessDenied` vs `NoSuchKey`
vs `PermanentRedirect`), queried from the target's egress IP rather than yours. That
taxonomy is owned by `../../cloud-exploitation/references/s3.md` — read it there.

**Corpus cases:** `3745647` — `h1/reports/3745647-adobe-triaged.md` (medium · triaged ·
bountied; the raw-IP filter beaten by wildcard DNS, with the no-bypass negative control
fired in the same session, and the trace-header correlation). `3748738` —
`h1/reports/3748738-adobe-triaged.md` (high · triaged; the two-message discriminator, the
proxy error page, and the same handler proven across five sibling engines).

## Reflected vs blind — decide the ceiling

- **Reflected**: the tool result / error message / a status endpoint returns the
  fetched body or a distinguishable error. This is high value — you can READ internal
  responses. Chase the reflection sink hard (`escalation.md`).
- **Blind**: nothing comes back. Use the oracles below to turn timing/status/length
  into a read, and lean on DNS-only confirmation for reach.

---

## Blind oracles — extract signal without reflection

### 1. DNS-only reach
The DNS hit proves the resolver fired even if HTTP egress is blocked. Enough to prove
the sink reaches out; combine with a metadata hostname (`sslip.io` form) to argue
internal reachability.

### 2. Timing differential (port scan by response time)
- **Open port** → fast connect, fast (or fast-failing) response.
- **Closed/filtered port** → hangs until the fetcher's connect timeout (seconds).
  Seen on an OpenAI-schema chat endpoint: ~1s open vs ~11s closed.

Loop over `127.0.0.1:<port>` and internal ranges; bucket by response time to map open
services. Keep it to a small, targeted port list (common service ports) — not a mass
sweep (rung 3 discipline; don't DoS).

### 3. Status / error-string differential (the strongest blind oracle)
The error text differs by what the fetch hit — this often lets you read state:
- image-proxy sink: `Media could not be read` (open, got bytes) vs `Access Denied` (closed).
- webhook-test sink: `invalid status code 403` (open, reached a service) vs
  `general_exception` (closed) vs `received successfully` (2xx).
- workflow-action sink: `500` on `127.0.0.1/<internal-route>` (open, same app) vs
  connection error (closed).
- libcurl strings: `Connection refused` (closed) vs `Connection timed out` (filtered)
  vs `Could not resolve host` (bad name) vs an HTTP-parse error (open, got a response).

Build a truth table of {error string → port state} from a couple of known-open and
known-closed probes, then scan.

### 4. Response-length differential
When status is constant but the body length varies by target — bucket by
`Content-Length` / body size to distinguish open vs closed, or 200-with-content vs
200-empty.

### 5. Boolean/HTTP-code differential
Some fetchers surface the upstream status code (`fetched, status 200/403/500`). A `200`
vs `403` vs `connection error` per target is a direct three-state oracle — use it to
walk metadata paths (`/latest/meta-data/` 200 vs a bogus path 404 confirms IMDS).

---

## From oracle to reported reach

Combine the strongest oracle with the metadata/loopback targets in
`cloud-metadata.md`:
- DNS-only + `169-254-169-254.sslip.io` → "SSRF reaches the metadata network" (Medium+,
  reachability stated).
- Status/error differential distinguishing `169.254.169.254/latest/meta-data/` (open)
  from a bogus IMDS path → "SSRF reaches AWS IMDS" (High-leaning).
- Any oracle that lets you read one metadata field / creds → the full escalation.

Report the concrete reach the oracle proved, never "the server made a request." A blind
port scan that maps an internal service (Redis 6379 open on loopback) is a reportable
internal reach; pair it with a plausible escalation from `escalation.md`.
