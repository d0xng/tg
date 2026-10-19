---
name: ffuf-web-fuzzing
description: "Perform baseline-driven ffuf discovery for hidden paths, files, extensions, parameters, virtual hosts, raw requests, and recursive content. Use when the user asks for ffuf, wordlists, directory or parameter fuzzing, soft-404 filtering, vhost discovery, or a missing route before testing a vulnerability class. Discovery is not a finding; route each meaningful hit to its owning skill and never brute-force credentials or spray exploit payloads through ffuf."
---

# ffuf-web-fuzzing — discovery is rung 0; the finding is what the path unlocks

> **`ffuf` is not on PATH — call it as `/run/host/usr/bin/ffuf`.** Verified
> working from an agent's shell (`ffuf version: 2.1.0-dev`). Agents run inside a
> Flatpak runtime whose `/usr/bin` is not the host's; the host's lives at
> `/run/host/usr/bin`, and Go-static binaries there run fine. Same for
> `/run/host/usr/bin/gau`. See `../_shared/references/tooling.md`.

ffuf is **surface-expansion tooling, not the exploit.** A 200 on `/admin`, a
discovered `id` parameter, a leaked `.git/` — none of these are findings. The
finding is the IDOR reached through the discovered endpoint, the AWS keys inside
the `.env`, the SSRF in the discovered webhook parameter. **Every ffuf run ends
in a handoff to an exploitation skill**, never in "found some interesting paths."

Climb the shared safe ladder (`../_shared/references/safe-ladder.md`): ffuf lives
on rungs 0–1 (enumerate, read your own responses); the moment a path is
confirmed, the exploiting skill climbs the rest. Never stop at the ffuf table.

## Rate discipline (non-negotiable)

- Start at `-rate 20 -t 20 -p 0.1-0.5 -se`; drop to `-rate 5 -t 5` on anything fragile.
- Stop on 429, repeated 403, timeouts, or connection errors. Degrading availability is out
  of bounds even in scope.
- Never brute-force credentials; never spray SQLi/XSS/command/destructive payloads through
  ffuf — it discovers surface, it does not prove injection.
- Wordlists: target-derived first, from `targets/<program>/wordlists/`; generic lists from
  `/opt/wordlists/SecLists/` (see `resources/WORDLISTS_LOCAL.md` for the real paths on this
  host). Full SecLists map: `resources/WORDLISTS.md`.
- Save JSON output under `targets/<program>/notes/`.
- `ffuf_helper.py` in this directory does three things you will want: `analyze` an ffuf JSON
  result set, `create-req` a raw-request template, and `wordlist` a numeric id range
  (`python3 ffuf_helper.py wordlist -o ids.txt -t numbers -s <start> -e <end>`).
- Raw-request templates for authenticated fuzzing (JWT, session+CSRF, API key, Basic,
  OAuth2, POST JSON, GraphQL): `resources/REQUEST_TEMPLATES.md`.
- On a new or materially changed job, cap the first run with `-maxtime 120` and read the
  JSON before letting it run long.

## Baseline first

Create a one-line wordlist containing a random path that cannot exist, then run a
small ffuf request with broad matching. Read the resulting JSON and record the
negative response's status, size, word count, line count, and stable body marker.

```text
targets/<program>/wordlists/baseline.txt:
nonexistent-path-7f31c9a2
```

```bash
ffuf \
  -u 'https://app.<host>/FUZZ' \
  -w targets/<program>/wordlists/baseline.txt \
  -mc all -rate 1 -t 1 \
  -o targets/<program>/notes/ffuf-baseline.json -of json
```

Inspect the JSON and apply one or more explicit filters to the real job:

- `-fs 4242`
- `-fw 312`
- `-fl 87`
- `-fr 'Page not found'`

`-ac` (auto-calibration) is supplementary. It must not replace the measured
baseline, because dynamic applications can calibrate away real endpoints.

## Content discovery

Prefer a small target-derived wordlist built from the collected JS. Escalate to a
generic SecLists list only when the targeted list is exhausted and automation is
allowed by the program.

```bash
ffuf \
  -u 'https://app.<host>/FUZZ' \
  -w targets/<program>/wordlists/js-paths.txt \
  -mc 200,201,204,301,302,307,401,403,405 \
  -fs 4242 -ac \
  -rate 20 -t 20 -p 0.1-0.5 -se \
  -o targets/<program>/notes/ffuf-paths.json -of json
```

## Wordlists — target-derived beats generic, always

SecLists is at **`/opt/wordlists/SecLists`** (full local map: `resources/WORDLISTS_LOCAL.md`;
use-case overview: `resources/WORDLISTS.md`).

| Use case | Path |
|---|---|
| Quick dirs | `/opt/wordlists/SecLists/Discovery/Web-Content/common.txt` |
| API routes | `/opt/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt` |
| Parameters | `/opt/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| Backups/config | `/opt/wordlists/SecLists/Discovery/Web-Content/Common-DB-Backups.txt`, `raft-large-files.txt` |
| Medium dirs | `/opt/wordlists/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` |
| Subdomains | `/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` |

### Recipe A — custom wordlist from the collected JS (highest hit rate)

```bash
mkdir -p targets/<program>/wordlists
grep -rhoE '"/[a-zA-Z0-9_./-]+"' targets/<program>/js/ \
  | tr -d '"' | sed 's#^/##' | sort -u > targets/<program>/wordlists/js-paths.txt
awk -F/ '{print $NF}' targets/<program>/wordlists/js-paths.txt \
  | sort -u > targets/<program>/wordlists/js-segments.txt
```

### Recipe B — derive a wordlist from app terms

```bash
grep -rhoE '[a-z][a-z0-9-]{3,}' targets/<program>/*.html targets/<program>/js/ \
  | sort | uniq -c | sort -rn | awk '$1>2{print $2}' \
  > targets/<program>/wordlists/app-terms.txt
```

Persist every custom list under `targets/<program>/wordlists/` so you never rebuild it.

## The high-value path hitlist (fuzz these deliberately)

These specific paths convert directly to a finding via handoff. Fuzz them as a tiny
explicit list, not buried in a 220k run:

```bash
mkdir -p targets/<program>/wordlists
cat > targets/<program>/wordlists/high-value.txt <<'EOF'
.git/config
.git/HEAD
.env
.env.local
.env.production
config.json
appsettings.json
docker-compose.yml
.aws/credentials
.npmrc
swagger.json
swagger/v1/swagger.json
openapi.json
api-docs
actuator
actuator/env
actuator/health
actuator/heapdump
actuator/mappings
server-status
phpinfo.php
wp-config.php.bak
web.config
backup.zip
db.sql
dump.sql
.DS_Store
EOF

ffuf -u https://<host>/FUZZ \
  -w targets/<program>/wordlists/high-value.txt \
  -mc 200,206,301,302,401,403 -fs <baseline> -t 15 \
  -o targets/<program>/notes/ffuf-highvalue.json -of json
```

What each hit becomes (the handoff, not the finding):
- **`.git/config` / `.git/HEAD` 200** → `git-dumper https://<host>/.git/ targets/<program>/notes/gitdump/`,
  reconstruct source, `git log -p --all | rg -i 'key|secret|password|token'` → `exposed-secrets`;
  the recovered source itself → `js-source-to-sink`.
- **`.env*`, `appsettings.json`, `.aws/credentials`, `.npmrc`** → read it, pull keys/DB
  creds/tokens, and **call the service to prove impact** → `exposed-secrets` (resolve each
  key against `../_shared/references/public-by-default-keys.md` first — a Stripe `pk_`,
  Sentry DSN, Maps key is SKIP; an `sk_live_`, Braze REST key, Azure `client_secret`, AWS
  `AKIA`, or DB password is PURSUE).
- **`swagger.json` / `openapi.json` / `api-docs` 200** → full endpoint + param map; feed
  every path/param to `idor-bola`, `ssrf-safe`, `sqli`.
- **`actuator/env` / `actuator/heapdump` (Spring Boot)** → env vars and heap dump leak
  creds/tokens → `exposed-secrets`; `actuator/gateway` can proxy → `ssrf-safe`.
- **`server-status` (Apache mod_status)** → live request URLs including other users'
  session-bearing paths → note in `targets/<program>/leads/`.

### Panel paths — the other high-value family

Admin/ops panels convert through a **documented vendor default credential**, not
through a config file, so they get their own tiny list and their own handoff:

```bash
cat > targets/<program>/wordlists/panels.txt <<'EOF'
api/health
login
jenkins/login
api/status
api/v1/version
v1/agent/self
api/v1/status/buildinfo
api/overview
phpmyadmin/
adminer.php
zabbix/index.php
nagios/
api/system/status
minio/health/live
vpn/index.html
global-protect/login.esp
dana-na/auth/url_default/welcome.cgi
owa/
EOF

ffuf -u https://<host>/FUZZ \
  -w targets/<program>/wordlists/panels.txt \
  -mc 200,301,302,401,403 -fs <baseline> -t 10 \
  -o targets/<program>/notes/ffuf-panels.json -of json
```

Any hit — including a `401` carrying a `WWW-Authenticate: Basic realm="<product>"`
— goes to **`infra-panels-default-creds`**: identify the product, pull its version
read-only, then send the bounded documented default. Panels answer on odd ports
far more often than app surfaces, so pair this with an `httpx -ports` sweep.
**Never fuzz credentials here** — a password list against a login form is the one
move that turns this class into an abuse complaint.

## Extensions

Use extensions only inside a directory already observed or strongly supported by
application artifacts.

```bash
ffuf \
  -u 'https://app.<host>/admin/FUZZ' \
  -w targets/<program>/wordlists/admin-files.txt \
  -e .json,.bak,.old,.config \
  -mc 200,401,403 -fs 4242 \
  -rate 15 -t 15 -p 0.1-0.5 -se \
  -o targets/<program>/notes/ffuf-admin-files.json -of json
```

## Parameter names

Fuzz benign parameter names and a harmless value. Do not use this mode to spray
exploit payloads.

```bash
ffuf \
  -u 'https://app.<host>/api/search?FUZZ=1' \
  -w /opt/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,400,401,403,405,500 \
  -fs 4242 -rate 15 -t 15 \
  -p 0.1-0.5 -se \
  -o targets/<program>/notes/ffuf-params.json -of json
```

A response difference is a lead, never a proof. Hand the exact endpoint+parameter
to the skill that owns the oracle:

| Signal ffuf surfaced | Hand to | Why not ffuf |
|---|---|---|
| Param reflects; a `'` changes the response or leaks `SQLSTATE`/`ORA-`/MySQL error text | `sqli` | needs a boolean/time/union oracle and read-only extraction, not `-mr` blasting |
| Value echoed into HTML/JS/an attribute | `xss` — it owns the payload arsenal, the context breakouts and the CSP-aware exfil ladder, whether the sink is stored or reflected. There is no separate reflected-XSS skill; a reflected hit still needs cross-user delivery to be payable | needs a context-aware payload plus an out-of-band callback and real render proof |
| Param takes a URL, host, or remote id | `ssrf-safe` | needs OOB confirmation, the filter-bypass ladder, and IMDS/internal reach |
| Endpoint takes an object id, or a `swagger` map of id-bearing routes | `idor-bola` | needs a cross-account/tenant proof on the safe ladder |
| Command-ish param, template markers, or an upload path | `rce-hunting` | needs sink confirmation and a real PoC, not payload spray |

## Authenticated own-session ID fuzzing (the most productive SAFE mode)

Fuzzing object IDs **inside your own authenticated session** is the fast path to an IDOR
primitive and it sits squarely on the safe ladder (own context, rungs 1–2). Endorsed, not
gated — there is no "human review before authenticated fuzzing" step.

1. Capture your authenticated request from the proxy to `targets/<program>/req.txt` and put
   `FUZZ` on the id (templates in `resources/REQUEST_TEMPLATES.md`):

   ```http
   GET /api/v1/orders/FUZZ HTTP/1.1
   Host: api.<host>
   Authorization: Bearer <your-own-token>
   Cookie: session=<your-own-session>
   ```

2. Fuzz a **small range around your own object's id** — not the whole table. Generate it
   with the helper in this directory:

   ```bash
   python3 ffuf_helper.py wordlist -o ids.txt -t numbers -s <mine-50> -e <mine+50>
   ffuf -request targets/<program>/req.txt -request-proto https -w ids.txt \
     -mc 200 -fw <your-own-response-word-count> -ac \
     -o targets/<program>/notes/ffuf-idor-probe.json -of json
   ```

3. **Safe-ladder stop rule:** a `200` on a neighbouring id whose body **differs from yours**
   is the IDOR signal. Read **one** neighbour **that you own** — seed a second object from
   your own second account and read it across (rung 1-2) — then **hand to `idor-bola`**. If
   the only differing body belongs to a **stranger on prod**, stop there and route per
   `validation`: rung 4 (redo the proof on `*-uat`/`*-oat`, using an operator-owned account) or
   rung 5 (not attempted: ask d0x directly before executing) — reading a real user's data on prod is never rung 3. Do
   **NOT** dump the range. Mass-harvesting other
   users' records "to show scale" is destructive: the program penalizes it and it adds no
   severity. One cross-object read proves the class; scale is stated by inference. If the
   ids are UUIDs/opaque, ffuf will not help — hand the endpoint to `idor-bola` for the
   id-source technique.

Raw-request fuzzing (`-request req.txt`) is the right tool for any complex auth (JWT, CSRF
token, custom headers) — see `resources/REQUEST_TEMPLATES.md`.

## Virtual hosts

Use vhost fuzzing only where wildcard/subdomain scope covers it. The `Host` header
carries `FUZZ`; the dial target stays the single in-scope IP/host.

```bash
ffuf \
  -u 'https://<host>/' \
  -H 'Host: FUZZ.<host>' \
  -w /opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,301,302,401,403 -fs 4242 \
  -rate 15 -t 15 -p 0.1-0.5 -se \
  -o targets/<program>/notes/ffuf-vhosts.json -of json
```

Every name that answered is also a dangling-DNS candidate. Resolve each one
(`dig +short CNAME FUZZ.<host>`); a third-party CNAME (S3/ngrok/YouTrack/WordPress/
Azure/Heroku/...), an apex answering NXDOMAIN, or a delegated NS answering
SERVFAIL/REFUSED goes to `subdomain-takeover` — that skill owns the fingerprint and
the claim gate. A vhost that 404s at the web layer is not a dead result until its DNS
has been checked.

## Recursion

Recursion is opt-in, bounded, and used only after a shallow run demonstrates
useful directories.

```bash
ffuf \
  -u 'https://app.<host>/FUZZ' \
  -w targets/<program>/wordlists/js-paths.txt \
  -fs 4242 -recursion -recursion-depth 2 \
  -maxtime-job 180 -rate 10 -t 10 \
  -p 0.1-0.5 -se \
  -o targets/<program>/notes/ffuf-recursive.json -of json
```

## Common false positives (fetch and read before flagging)

- Static asset dirs (`/assets`, `/static`, `/dist`) — always 200, almost always boring.
- SPA catch-all — every path returns `index.html` at the same size; discriminate by
  size/body, not by status.
- WAF/CDN (Cloudflare/Akamai) challenge pages — 200 with a challenge body; the measured
  baseline catches these, `-ac` alone often does not.

## Finish and handoff

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

Review candidates against the baseline, fetch the minimal proof for each, then write
the lead:

```bash
# extract the interesting hits from the JSON
jq -r '.results[] | "\(.status) \(.length) \(.url)"' \
  targets/<program>/notes/ffuf-paths.json | sort -u

# deeper triage of the same result set
python3 ffuf_helper.py analyze targets/<program>/notes/ffuf-paths.json
```

Then write one lead file per promising hit into `targets/<program>/leads/` in the
format in `../_shared/references/output-contract.md` — **Group:** `endpoint`,
the exact URL as target, the baseline-vs-hit metadata as evidence, and the skill you
are handing it to as the next step. Routing:

```text
- `.git/`, `.env`, `appsettings`, `/actuator/env`  → `exposed-secrets`, `js-source-to-sink`
- `swagger.json`, `/api/**`                        → `idor-bola`, `ssrf-safe`, `sqli`
- `?url=` / `?image=` / a webhook param            → `ssrf-safe`
- `/orders/{id}`, `/users/{id}`, `?account=`       → `idor-bola`
- a product panel (`/api/health`, `X-Jenkins`, Basic realm) → `infra-panels-default-creds`
- a vhost serving a different app                  → new target dir + `js-source-to-sink`
- a vhost/subdomain hit that resolves to a third-party CNAME, answers NXDOMAIN at
  the apex, or whose delegated NS answers SERVFAIL/REFUSED → `subdomain-takeover`
```

Any vhost/subdomain result set is also a takeover worklist: `dig +short CNAME` each
name that answered, and route the third-party / dangling ones to `subdomain-takeover`
before discarding them as "no content found".

Notes discipline (the funnel in `../_shared/references/output-contract.md`):

- raw JSON + the baseline measurement → `targets/<program>/notes/`
- promising hits with their handoff target → `targets/<program>/leads/`
- reusable custom wordlists → `targets/<program>/wordlists/`
- a one-line dead-end note before you drop a fuzz angle, so future-you does not
  re-walk it

Store raw bodies, authenticated requests, tokens, and PII only under
`targets/<program>/notes/`, redacted in anything that becomes a lead or a report.

**The rule in one line:** ffuf expands the surface; the finding is proven by the
exploit skill you hand the surface to. Never end an ffuf run at the table.
