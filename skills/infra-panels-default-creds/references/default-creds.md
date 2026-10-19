# Default-credential matrix and the bounded-set discipline

## The rule of this skill

**A small bounded set of documented vendor defaults is authorized testing. A
password list is an attack.**

The difference is not the number of requests, it is what the requests *are*. A
documented default is a **configuration check**: the vendor published the
credential, the deployment guide told the operator to change it, and you are
verifying that they did. A password list is **credential guessing**, which nearly
every program's policy bans outright and which a triager reading the access log
will classify as an attack regardless of what your report says.

Operating limits, non-negotiable:

- **Two credential pairs per product, maximum, one attempt each.** Every pair
  comes verbatim from the matrix below.
- **Stop on the first success.** Stop when the set is spent. **There is never a
  third guess.**
- **Every pair must be traceable to a source** — the vendor's own documentation,
  or a shipped `nuclei` `http/default-logins/` template that encodes the same
  pair. If you cannot name where it came from, you are guessing; do not send it.
- **Never lock or throttle an account.** Zabbix blocks after 5 consecutive
  failures by default; appliances and AD-backed OWA carry configurable lockout
  policies. A locked administrator is a real outage you caused, on a real system,
  for nothing.
- **Never change the password** even when the panel demands it — see
  `post-login-proof.md`.

**Banned outright**: `hydra`, `medusa`, `patator`, `ncrack`; `ffuf` or `sqlmap`
pointed at a login form; any SecLists password file; any credential wordlist,
including "top 10"; username enumeration as an objective; and the nuclei
templates that iterate a password list (named in `nuclei-driver.md`).
`../../ffuf-web-fuzzing/SKILL.md` states the same prohibition — never
brute-force credentials.

## The matrix

Sources: `vendor` = the product's own documentation; `nuclei` = the pair shipped
in `~/nuclei-templates/http/default-logins/`, inspected on this host.

| Product | Documented default(s) | Where it is sent | Source | Lockout risk |
|---|---|---|---|---|
| **Grafana** | `admin:admin`; `admin:prom-operator` | `POST /login` JSON | vendor (`admin/admin` on first boot); nuclei ships both | low — Grafana has brute-force protection, but two attempts never trips it. `prom-operator` is the kube-prometheus-stack Helm chart default and is worth the second slot on any Kubernetes-adjacent host. |
| **Airflow** | `airflow:airflow` | `POST /login/` form, or Basic on `/api/v1/*` | vendor — the docker-compose quick start states "The default account has the login `airflow` and the password `airflow`" | low |
| **RabbitMQ** | `guest:guest` | Basic on `/api/overview` | vendor; nuclei | low. RabbitMQ's docs state `guest` "is prohibited from connecting from remote hosts; it can only connect over a loopback interface", so a **remote** `guest:guest` success means the operator edited `loopback_users` — worth saying in the report, it rules out "that is the default, it is fine". |
| **Zabbix** | `Admin:zabbix` (capital A) | `POST /index.php` or `/zabbix/index.php` | vendor; nuclei | **throttles** — 5 consecutive failures pauses the interface for 30s (defaults "Login attempts: 5" / "Login blocking interval: 30s"). Two attempts is safe; a list is not, and it produces the "account is temporarily blocked" error the admin will see. |
| **Nagios Core / XI** | `nagiosadmin:nagiosadmin`; XI also `root:nagiosxi` | Basic on `/nagios/`, or the XI login form | nuclei (`nagios-default-login.yaml`, `nagiosxi-default-login.yaml`) | medium — Apache Basic auth does not lock, the XI app can |
| **MinIO** | `minioadmin:minioadmin` | console login (`:9001` by default) | vendor; nuclei | low |
| **Keycloak** | `admin:admin` | `POST /realms/master/protocol/openid-connect/token`, `client_id=admin-cli`, `grant_type=password` | vendor — the getting-started guide sets `KC_BOOTSTRAP_ADMIN_USERNAME=admin` / `KC_BOOTSTRAP_ADMIN_PASSWORD=admin` (older builds: `KEYCLOAK_ADMIN`) | medium — realm brute-force detection may be on |
| **Citrix NetScaler** | `nsroot:nsroot` (the docs say to use the default password, which equals the user name; on MPX hardware it may instead be the chassis serial number) | **management interface only** (NSIP GUI/SSH) | vendor | **high consequence** — account-lockout policy is configurable on these appliances and a locked appliance administrator is a production outage. One attempt, only if the management interface is an in-scope asset. |
| **PAN-OS / GlobalProtect** | `admin:admin` | **management interface only** | vendor; the default must be changed at first login since PAN-OS 9.0.4, so it survives only on older or upgraded-in-place devices | **high consequence** — same reasoning. Only if the management interface is an in-scope asset. |
| **Elasticsearch / Kibana** | `elastic:changeme` — **5.x only** | Basic on `/` | vendor — removed in 6.0 in favour of an auto-generated bootstrap password | low, but the pair is dead on anything modern. Send it only if the fingerprint says 5.x. |

## Products with NO default credential — do not guess one

For these, a "default creds" angle does not exist. Sending invented pairs at
them is guessing, and it is the single fastest way to turn this class into an
abuse complaint. Each row names what to do instead.

| Product | Why there is no default | Do this instead |
|---|---|---|
| **Jenkins** | The setup wizard generates a random `initialAdminPassword`. | Test **anonymous read**: `/whoAmI/api/json`, `/api/json`, `/script`. See `fingerprints.md`. |
| **Portainer** | The admin password is set on first run. | Check `/api/users/admin/check` — a `404` is an uninitialized instance (rung 5, do not init). |
| **Adminer** | It is a DB client, not a service — it has no accounts of its own. | Version disclosure only. It authenticates against a **database**, and pointing it at one is a connection you initiate to a host that may not be in scope. |
| **phpMyAdmin** | Same — it fronts MySQL/MariaDB. The `root` account belongs to the database. | If the program's scope covers the database, `root` with an **empty** password is the documented MySQL default and is worth one bounded attempt. `root:root`, `root:123456`, `root:toor` are **guesses** — the shipped nuclei template iterates them, and you must not. |
| **Consul** | ACLs are off by default; there is no login at all. | The exposure *is* the finding: `/v1/catalog/services`, `/v1/kv/?recurse`. Owner is `exposed-secrets`. |
| **Prometheus** | No authentication in the product at all. | Same — `/api/v1/targets` and `/api/v1/status/config` are the exposure. |
| **Spring Boot Actuator** | Not a panel with accounts. | `/actuator/env` + `/actuator/heapdump` are a data exposure → `exposed-secrets`. |
| **Ivanti / Pulse Connect Secure** | Admin credentials are set at provisioning. | Version disclosure, then the verified CVE map in `fingerprints.md` → `rce-hunting`. |
| **Exchange / OWA** | Credentials are the organisation's AD accounts. | Version fingerprint only — **and that fingerprint alone closed N/A for d0x** (Vienna #b645a7ab). Never send AD credentials at it. |

## Sending the credential (rung 2 — one request)

Two forms cover almost everything. Capture the response in full; the failure body
is your negative control.

**JSON login (Grafana):**

```bash
curl -s -i -c graf.jar -X POST "$H/login" \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","password":"admin"}'
# success -> HTTP/1.1 200 OK
#            Set-Cookie: grafana_session=<32 hex>; Path=/; HttpOnly
#            {"message": "Logged in", "redirectUrl": ""}
# failure -> HTTP/1.1 401  {"message": "Invalid username or password"}
```

**HTTP Basic (RabbitMQ, Airflow API, Nagios):**

```bash
curl -sD - -o /dev/null "$H/api/overview"        # -> 401 WWW-Authenticate: Basic realm="RabbitMQ Management"
curl -s -u guest:guest "$H/api/overview" | jq -c '{rabbitmq_version, object_totals}'
# -> {"rabbitmq_version":"3.11.5","object_totals":{"queues":214,"connections":88,"consumers":130}}
```

**OAuth password grant (Keycloak):**

```bash
curl -s -X POST "$H/realms/master/protocol/openid-connect/token" \
  -d 'client_id=admin-cli' -d 'grant_type=password' \
  -d 'username=admin' -d 'password=admin' | jq -r '.token_type, .scope'
# success -> Bearer / profile email
# failure -> .error = invalid_grant
```

Record, for every attempt: the exact pair sent, its source row above, the status,
and the response body. Two attempts is the whole budget — if both fail, write the
one-line dead-end note (`grafana 9.3.2 on <host>: admin:admin and
admin:prom-operator both 401 — default-cred angle dead`) and rotate to another
angle on the same boundary.

Then go to `post-login-proof.md` — a successful login with nothing read back is
still not a finding.
