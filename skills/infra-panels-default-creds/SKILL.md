---
name: infra-panels-default-creds
description: "Assess exposed infrastructure, administration, monitoring, VPN, and operations panels using product fingerprints and a small bounded set of documented vendor defaults. Use when recon finds a named panel, actuator or health endpoint, product header, Basic or NTLM challenge, default-login template hit, uninitialized-admin check, or version API. A banner alone is not a finding; never use password lists or brute force."
---

# infra-panels-default-creds — the login converts, the version banner does not

This is d0x's only **triaged infrastructure** finding class, and it has exactly
one shape that pays: a panel that still accepts the credential its vendor
published, entered once, reading real administrative data. Everything around
that shape — the version banner, the exposed login page, the CVE the build is
theoretically vulnerable to — is **rung 1 noise that programs close as N/A**.

The evidence is d0x's own, from
`~/Desktop/skills/targets/_shared/gadgets/corpus-playbook/04-cve-cms-rce-ato.md`
("Default credentials / version-disclosing infra panels"):

- **uipath Grafana #3701766** — `admin:admin`, full SRE infrastructure inventory
  and 14 users read back → **triaged** (capped low: staging instance).
- **Vienna Exchange #b645a7ab** — `X-OWA-Version` build fingerprint only, no
  login → **N/A**.

So: **default creds with real admin data = triaged; pure version fingerprint =
N/A. Default creds beat CVE fingerprinting every time.** Climb the shared safe
ladder (`../_shared/references/safe-ladder.md`) to the login and the read, then
stop dead.

> **ALREADY REPORTED — reuse the technique, not the report.** The Grafana
> `admin:admin` play and the Exchange fingerprint are both already in d0x's
> corpus. Apply the methodology to **new hosts and new products**; never
> re-surface the same panel on the same target.
>
> Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Read-on-demand references

Keep the trigger map (below) internalized; open a reference the moment you have
a candidate product.

- `references/fingerprints.md` — the **unauthenticated fingerprint request per
  product**: what to send, what comes back, where the version lives, and the
  verified version→CVE map. Open it to identify a panel and to pull its version
  read-only.
- `references/default-creds.md` — the **default-credential matrix** (product →
  documented vendor default → source → lockout risk) and the products that have
  **no** default at all. Also carries the bounded-set discipline in full. Open it
  before you send a single credential.
- `references/post-login-proof.md` — the **read-only post-login proof set per
  product**: the two or three calls that show real admin data, the negative
  control, and the rule that you never change the password even when the panel
  demands it. Open it the instant a login succeeds.
- `references/nuclei-driver.md` — driving `nuclei` over an httpx host list at
  critical/high, which template families to exclude, and the **mandatory manual
  verification pass** for every hit. Open it when you have more than a handful of
  hosts.
- `../_shared/references/output-contract.md` — where results go: the
  notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim`
  dedup key, and the severity enum.

Also import `../_shared/references/safe-ladder.md` (how far to climb) and
`../_shared/references/tooling.md` (`nuclei`, `httpx`, `curl`, `jq` are all
present on this host).

**Recognition, not duplication.** Reaching an admin surface with **no**
credential — path normalization, `X-Original-URL`, proxy/cache ACL differentials,
`/manager/html`, `/server-status` — belongs to
`../auth-flow-bypass/references/acl-proxy-cache.md`. Discovering the panel path
in the first place belongs to `ffuf-web-fuzzing`. This skill starts once you know
which product is answering and owns exactly one move: **the documented default
credential, and the read that follows it.**

## The rung map (state the rung for every step you take)

| Rung | Action here | Rule |
|---|---|---|
| **1** | Unauthenticated fingerprint: `/api/health`, `X-Jenkins`, `apiinfo.version`, `X-OWA-Version`, a Basic realm. | Always safe, always first. **Never a finding on its own.** |
| **2** | **One** login attempt with a documented vendor default, on a panel d0x pointed you at. | Bounded set only — `references/default-creds.md`. Stop on first success; stop when the bounded set is spent. |
| **3** | Read administrative data read-only — stats, org list, user list, job list, queue counts. | **Stops at proof.** Two or three calls. Never paginate the estate, never export. |
| **4** | If the RoE confines privacy/privesc proofs to UAT/OAT, do the rung-3 read on the `*-uat`/staging panel and infer prod. | Relocates the proof, does not cancel it. |
| **5** | **Changing anything — including the password.** Also: creating a user, initializing an uninitialized admin, saving a dashboard, triggering a job, writing a KV key. | **Not attempted: ask d0x directly before executing.** The "update your password" prompt is the oracle, not an instruction — see below. |

**The prompt IS the confirmation.** When Grafana (or any panel) answers a
successful default login by demanding a password change, that demand proves the
credential is *still* the vendor default. Screenshot it, quote it, and **skip the
change**. Changing it is rung 5, it locks the operator out of their own panel,
and it destroys the very evidence you came for.

## Method

1. **Identify the product** from the marker you already have — `references/fingerprints.md`.
2. **Fingerprint unauthenticated (rung 1).** Pull the version by its documented
   path. Record the exact request and response in `targets/<program>/notes/`.
3. **Resolve whether a documented default exists** — `references/default-creds.md`.
   - **No documented default** (Jenkins, Portainer, Adminer, Ivanti, bare
     Consul/Prometheus): you have a *fingerprint*, which is N/A on its own. Do
     not report it. Route it instead — an unauthenticated Consul/Prometheus/
     Elasticsearch/actuator surface is a **data exposure**, not a credential bug,
     and its owner is `exposed-secrets`; a build matching a verified RCE CVE goes
     to `rce-hunting`. If neither applies, write the dead-end note and rotate.
   - **Documented default exists**: continue.
4. **One bounded login attempt (rung 2).** One pair, one request. Then at most
   one alternate documented pair. Never a third guess, never a list.
5. **On success, run the product's read-only proof set (rung 3)** —
   `references/post-login-proof.md` — plus the unauthenticated negative control
   on the same endpoint. Then stop.
6. **Sweep the rest of the host list with `nuclei`** — `references/nuclei-driver.md` —
   and manually re-prove every hit by hand before it becomes a lead.
7. Write the lead, run `validation`, then `report-writing`.

## Trigger map — marker → product → first move

| You see (marker) | Product | First move (rung 1) | Reference |
|---|---|---|---|
| `{"commit":…,"database":"ok","version":"9.3.2"}` on `/api/health` | Grafana | read `.version`; then the bounded `admin:admin` / `admin:prom-operator` pair | `fingerprints.md`, `default-creds.md` |
| `X-Jenkins: <ver>` / `X-Hudson` header, `Sign in [Jenkins]` | Jenkins | `GET /whoAmI/api/json` — anonymous read is the bug, there is no default cred | `fingerprints.md` |
| `/api/status` → `.version.number`, `kibanaWelcomeView` | Kibana / Elasticsearch | `GET /` for `"You Know, for Search"`; `_cat/indices` if open | `fingerprints.md` |
| `/actuator` link index, `application/vnd.spring-boot.actuator.v3+json` | Spring Boot | `GET /actuator/env`, `GET /actuator/heapdump` (`JAVA PROFILE 1.0.2`) | `fingerprints.md` → `exposed-secrets` |
| `/api/v1/version` → `{"version":"2.5.1"}` | Airflow | version read; then bounded `airflow:airflow` | `default-creds.md` |
| `/v1/agent/self` → `.Config.Version`, `/v1/catalog/services` | Consul | catalog read — no auth by default, so this is exposure not creds | `fingerprints.md` → `exposed-secrets` |
| `/api/v1/status/buildinfo` → `.data.version` | Prometheus | `/api/v1/targets` (internal host inventory), `/api/v1/status/config` | `fingerprints.md` → `exposed-secrets` |
| `WWW-Authenticate: Basic realm="RabbitMQ Management"` | RabbitMQ | bounded `guest:guest` on `/api/overview` | `default-creds.md` |
| `/realms/master/.well-known/openid-configuration` | Keycloak | discovery read; bounded `admin:admin` password grant on `admin-cli` | `default-creds.md` |
| `Set-Cookie: phpMyAdmin=`, `pmahomme` theme | phpMyAdmin | version via `/doc/html/index.html`; the creds are the **DB's**, not pma's | `default-creds.md` |
| `<title>Login - Adminer</title>` + `class="version">4.8.1` | Adminer | version read only — no product default exists | `default-creds.md` |
| `{"jsonrpc":"2.0","result":"6.0.13"}` from `apiinfo.version` | Zabbix | unauth version via JSON-RPC; then bounded `Admin:zabbix` (**lockout risk**) | `fingerprints.md`, `default-creds.md` |
| `WWW-Authenticate: Basic realm="Nagios Access"` | Nagios | bounded `nagiosadmin:nagiosadmin` | `default-creds.md` |
| `/api/system/status` → `{"Version":"2.16.2"}` | Portainer | `GET /api/users/admin/check` — a `404` is an **uninitialized admin** (rung 5) | `fingerprints.md` |
| `Server: MinIO`, `x-minio-deployment-id` | MinIO | bounded `minioadmin:minioadmin` on the console | `default-creds.md` |
| `NSC_AAAC`/`NSC_TEMP`/`NSC_PERS` cookies, `/vpn/index.html` | Citrix NetScaler | fingerprint only on the gateway; `nsroot:nsroot` applies to the **management** plane | `fingerprints.md` |
| `/global-protect/login.esp`, `/ssl-vpn/getconfig.esp` | PAN-OS GlobalProtect | portal fingerprint; `admin:admin` applies to the **mgmt** interface only | `fingerprints.md` |
| `dana-na` paths, `DSID`/`DSSIGNIN` cookies | Ivanti / Pulse Connect Secure | `/dana-na/nc/nc_gina_ver.txt` → `ProductVersion` | `fingerprints.md` |
| `WWW-Authenticate: NTLM` on `/EWS`, `/rpc`, `/mapi`, `/autodiscover`, `/Microsoft-Server-ActiveSync` | Windows integrated auth (Exchange, IIS, SharePoint, ADFS, RDWeb) | send the fixed Type 1 blob, decode the Type 2 → internal AD domain/host/FQDN + OS build | `fingerprints.md` |
| `X-OWA-Version`, `X-FEServer` | Exchange / OWA | `/ecp/Current/exporttool/…` for the exact build | `fingerprints.md` |

## The credential discipline — the rule of this skill

**A small bounded set of documented vendor defaults is authorized testing. A
password list is an attack.** Programs read the request log, not your intent, and
that single distinction is what keeps this class triaged instead of escalated to
abuse.

- **Bounded means bounded**: at most **two** credential pairs per product, taken
  verbatim from `references/default-creds.md`, **one attempt each**. Stop on the
  first success. Stop when the set is spent. There is never a third guess.
- **Every pair must be traceable to vendor documentation** (or to a shipped
  nuclei `default-logins` template, which encodes the same). If you cannot name
  the source, you are guessing — do not send it.
- **Banned outright, no exceptions**: `hydra`, `medusa`, `patator`, ffuf or
  sqlmap against a login form, any SecLists password file, any credential
  wordlist, any nuclei template that iterates a password list
  (`references/nuclei-driver.md` names them), and username enumeration as a goal.
  `ffuf-web-fuzzing` states the same prohibition — never brute-force credentials.
- **Never lock or throttle an account.** Zabbix blocks after 5 consecutive
  failures by default; NetScaler, PAN-OS and AD-backed OWA carry configurable
  lockout policies. A locked administrator is a real outage you caused. One
  attempt at the documented default, then stop.
- **Never change the password**, even when the panel insists (rung 5).
- **Never initialize an uninitialized panel** (Portainer's `404` on
  `/api/users/admin/check`, a first-run setup wizard). Creating the admin account
  is a write that hands you the instance and denies it to the owner — report the
  reachable uninitialized state, and ask d0x directly before executing rather than touching it.

## The conversion rule (grade honestly before you spend a turn)

| Claim | Verdict | Evidence |
|---|---|---|
| Documented default accepted **and** real admin data read back | **Triaged** — this is the class | uipath Grafana #3701766 (`admin:admin` → SRE infra inventory + 14 users) |
| Version banner / build number only, no login | **N/A** | Vienna Exchange #b645a7ab (`X-OWA-Version` fingerprint, closed N/A) |
| "Version X is vulnerable to CVE-Y" with no exploitation | **N/A** — the same closure, differently worded | Card 04's Apache `2.4.66` fingerprint reports also closed informative |
| Login page merely reachable / panel exposed | **N/A** | Panel exposure is rung 1 |
| Default creds on a **staging / non-prod** instance | **Triaged, capped low** | uipath was triaged *but low* because it was staging |
| Default creds → panel that then leaks credentials, a heapdump, cloud keys, or an internal host inventory | **High and up** — but the finding is now the leaked material | Hand to `exposed-secrets` / `cloud-exploitation` |

Three framings that keep a real one out of the N/A pile:

1. **Lead with the data, not the door.** Title it by what was read
   ("Grafana admin panel accepts default credentials, exposing 14 staff accounts
   and 19 production datasource configurations"), never "default credentials
   found".
2. **State prod-vs-staging yourself.** A triager who discovers on their own that
   it is staging downgrades and distrusts the rest. Saying "this is the staging
   instance; the same image runs prod behind SSO" is honest and holds severity
   better than silence.
3. **Attach the negative control.** The same endpoint without the session
   returning `401` is what proves the credential — not the panel — is the
   boundary you crossed.

If your candidate is a version banner and nothing else, it is not a finding. Do
not write it up, do not "mention it for completeness". Note the version in
`notes/`, check it against the verified CVE map in `references/fingerprints.md`,
and rotate.

## Evidence checklist (the triager re-proves it — make it self-contained)

Captured into `targets/<program>/notes/` as you go:

- **The fingerprint** — the exact rung-1 request and the version/marker it
  returned, naming the product.
- **The credential and its source** — the documented default you used, and the
  vendor page or nuclei template it came from. State plainly that it was a single
  attempt from a bounded set.
- **The successful login** — status, the session cookie/token *field name* with
  its value redacted (`grafana_session=<redacted, len=32>`), and the
  "update password" prompt if the panel raised one.
- **The negative control** — the same admin endpoint with no session returning
  `401`/`403`, and a wrong-password attempt returning the failure body.
- **The admin data read (rung 3)** — the two or three read-only responses, with
  counts intact and PII redacted: `"users": 14`, the org names, the datasource
  names and internal URLs, the DAG/job/queue names.
- **Environment** — prod or staging, stated explicitly, with how you determined it.
- **State statement** — an explicit line that nothing was created, modified or
  deleted, and that the password was deliberately left unchanged.

Then write the lead or finding to `targets/<program>/` per
`../_shared/references/output-contract.md`. Use **Group:** `logic-misconfig` and keep the claim string stable — name the **product + host +
credential + what was read** ("Grafana grafana-stg.target.com default
admin:admin → 14 users + 19 datasources"), never just "default credentials", or
the same panel reads as new next session.

## Non-destructive rules

- Rung 1 fingerprinting is unlimited; rung 2 is **one attempt per documented
  pair, two pairs maximum**; rung 3 is **two or three read-only calls**.
- Never change a password, never create or delete a user, never initialize an
  uninitialized instance, never save a dashboard, never trigger a job or pipeline,
  never write a KV key, never purge a queue. All rung 5 — not attempted: ask d0x directly before executing.
- Never run a credential list, and never leave a panel account locked.
- A heapdump or `env` dump is **evidence**: download it once, keep it in
  `notes/`, redact every value in anything that leaves that directory, and flag
  every credential it contains for rotation.
- Do not scan or log in on hosts d0x did not hand you. Scope is a safety
  boundary; the panel he pointed at is authorized.
- If the program's RoE confines this class to UAT/OAT, do the login and the read
  there (rung 4) and infer prod.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- Panel leaks credentials or key material — `/actuator/env`, `/actuator/heapdump`,
  a Grafana datasource `basicAuthUser` + internal URL, Consul KV, a Prometheus
  scrape config, an Airflow connection — → `exposed-secrets` (identify the
  service and call its API read-only; existence is rung 0 there too).
- Those credentials are cloud credentials — an `AWS_SECRET_ACCESS_KEY` in the
  actuator env, MinIO/S3 keys, a CloudWatch/Azure Monitor datasource, an IMDS
  reachable from the panel host — → `cloud-exploitation`.
- The panel's disclosed version matches a **verified** RCE CVE in
  `references/fingerprints.md`, or the panel ships an execution surface (Jenkins
  `/script`, a Grafana datasource proxy, an Airflow DAG-trigger) → `rce-hunting`.
- The panel is reachable only past a `403` you want to normalize, or the login is
  bypassable without any credential → `../auth-flow-bypass/references/acl-proxy-cache.md`,
  and `broken-access-control` for the function-level gap.
- The panel path is not known yet → `ffuf-web-fuzzing` (its high-value hitlist
  points back here).
- About to claim anything → `validation` first, then `report-writing`.

**The rule in one line:** the version banner is rung 1 and closes N/A — the
finding is one documented default credential accepted, and the administrative
data you read back before touching nothing.
