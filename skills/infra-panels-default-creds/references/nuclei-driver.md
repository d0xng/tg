# Driving nuclei over a host list — and why every hit still gets verified by hand

`nuclei` is installed on this host (`~/go/bin/nuclei`, v3.7.0, templates in
`~/nuclei-templates`) — see `../../_shared/references/tooling.md`. It is the only
efficient way to ask a hundred hosts "which of you is a panel, and which of you
still answers to the vendor default".

**nuclei output is a lead, never a finding.** Its severity field is the template
author's opinion about the class, not a judgement about this target; its matchers
fire on strings, not on impact; and a report built from a nuclei line reads like a
scanner dump to a triager and closes accordingly. **Every hit gets a manual
verification pass before it becomes a lead** — that pass is mandatory and is
specified at the bottom of this file.

## Build the host list first

Panels answer on non-standard ports far more often than app surfaces do, so
resolve and probe before scanning. `recon` owns wildcard/CIDR expansion; this
consumes its output.

```bash
mkdir -p targets/<program>/notes

httpx -l targets/<program>/hosts.txt \
  -ports 80,443,3000,5601,7001,8000,8080,8081,8443,8834,9000,9001,9090,9200,9443,15672 \
  -status-code -title -tech-detect -silent \
  -o targets/<program>/notes/httpx-panels.txt
```

Skim the titles first — `Grafana`, `Sign in [Jenkins]`, `Kibana`, `Portainer`,
`phpMyAdmin`, `Citrix Gateway`, `GlobalProtect Portal` are all visible right
there, and a title match plus `fingerprints.md` beats a scan every time. Feed the
URL column to nuclei only for the hosts you did not already identify.

## The run

```bash
awk '{print $1}' targets/<program>/notes/httpx-panels.txt \
  > targets/<program>/notes/panel-hosts.txt

nuclei -l targets/<program>/notes/panel-hosts.txt \
  -t http/default-logins/ -t http/exposed-panels/ -t http/misconfiguration/ \
  -s critical,high \
  -etags cors,ssl,dns,waf,intrusive,fuzz,dos,brute-force \
  -rl 20 -c 10 -timeout 5 -retries 1 -ni -duc \
  -j -o targets/<program>/notes/nuclei-panels.json
```

Flags that matter:

| Flag | Why |
|---|---|
| `-s critical,high` | the operator does not report the rest; medium is worth one pass on a small list, never on a large one |
| `-etags …` | drops the families below before they are ever sent |
| `-rl 20 -c 10` | rate limit 20/s, 10 concurrent — the same discipline `ffuf-web-fuzzing` applies. Degrading availability is out of bounds even in scope. |
| `-timeout 5 -retries 1` | appliances are slow and retries multiply login attempts |
| `-ni` | no interactsh; keep OOB deliberate, `ssrf-safe` owns it |
| `-duc` | no auto-update mid-engagement, so the run is reproducible |
| `-j -o …` | JSONL to `notes/`, which is where raw evidence belongs |

Triage the JSONL (the `@tsv` form — string interpolation inside a shell-quoted
jq filter is where this line usually breaks):

```bash
jq -r '[.info.severity, ."template-id", ."matched-at"] | @tsv' \
  targets/<program>/notes/nuclei-panels.json | sort -u
```

Real output from an authoring run against a local lab panel:

```text
high     grafana-default-login   http://127.0.0.1:8899/login
critical springboot-heapdump     http://127.0.0.1:8899/actuator/heapdump
```

Two lines. Two leads. **Zero findings** until step "The mandatory verification
pass" below has been run on each.

## Template families to skip, and why

Excluded because the operator does not report them, so sending them is pure noise
and pure request budget:

| Family / tag | Reason |
|---|---|
| `cors` | never reported, never mentioned. Hard exclusion. |
| `headers`, `weak-hsts-detect`, `cookies-without-httponly`, `xss-deprecated-header` | missing security headers and cookie flags are auto-discarded — `../../validation/references/auto-discard.md` |
| `ssl`, `tls`, expired/self-signed certificate templates | informational; on appliances it is the norm |
| `tech`, `detect`, `favicon-detect`, `fingerprinthub-web-fingerprints` | pure fingerprinting — that is `fingerprints.md`'s job, done more precisely and with fewer requests |
| `info` severity generally | a panel being reachable is rung 1 |
| `dos`, `intrusive`, `fuzz` | may degrade the target; out of bounds even in scope |
| `token-spray` | sends credentials/keys to third-party APIs |
| `osint`, `honeypot` | not the target |

## Templates that violate the bounded-set rule — exclude them by id

Some `default-logins` templates are credential **lists**, not vendor defaults.
Running them is the brute force this skill bans, and it is how you lock an
administrator out. Counts below were measured from the templates on this host:

| Template | Login attempts it sends | Verdict |
|---|---|---|
| `http/default-logins/apache/tomcat-default-login.yaml` | **28** | brute force — exclude |
| `http/default-logins/couchdb/couchdb-default-login.yaml` | 4 passwords x 4 users, clusterbomb = **16** | exclude |
| `http/default-logins/jellyfin/jellyfin-default-login.yaml` | **12** | exclude |
| `http/default-logins/oracle/peoplesoft-default-login.yaml` | **10** | exclude |
| `http/default-logins/phpmyadmin/phpmyadmin-default-login.yaml` | 4 passwords x 2 users = **8** | exclude — and the passwords are DB guesses (`123456`, `toor`), not a phpMyAdmin default |
| `http/default-logins/weblogic/weblogic-weak-login.yaml` | **8** | exclude |
| `http/default-logins/adminer-default-login.yaml` | **5** | exclude — Adminer has no default of its own |

Acceptable, because each sends a bounded documented pair:
`grafana/grafana-default-login.yaml` (2, pitchfork),
`rabbitmq/rabbitmq-default-login.yaml` (1), `zabbix/zabbix-default-login.yaml` (1),
`minio/minio-default-login.yaml` (1), `apache/airflow-default-login.yaml` (1),
`nagios/nagios-default-login.yaml` (2, pitchfork).

`-eid` takes template **ids**, not paths, and it does drop them — loading only
`tomcat-default-login.yaml` reports `Templates loaded for current scan: 1`, and
adding `-eid tomcat-default-login` turns that into
`no templates provided for scan`.

Exclude by id on the command line:

```bash
nuclei -l targets/<program>/notes/panel-hosts.txt \
  -t http/default-logins/ -t http/exposed-panels/ -t http/misconfiguration/ \
  -s critical,high \
  -etags cors,ssl,dns,waf,intrusive,fuzz,dos,brute-force \
  -eid tomcat-default-login,phpmyadmin-default-login,adminer-default-login,\
couchdb-default-login,jellyfin-default-login,peoplesoft-default-login,weblogic-weak-login \
  -rl 20 -c 10 -timeout 5 -retries 1 -ni -duc \
  -j -o targets/<program>/notes/nuclei-panels.json
```

**Pre-flight any default-login template you are unsure about** — read its
`payloads:` block before you send it. This counts the passwords it will try:

```bash
preflight() {
  awk '/^[[:space:]]+password:/{f=1;n=0;next} f&&/^[[:space:]]+- /{n++;next} f{print n;f=0;exit} END{if(f)print n}' "$1"
}
preflight ~/nuclei-templates/http/default-logins/grafana/grafana-default-login.yaml   # -> 2
preflight ~/nuclei-templates/http/default-logins/apache/tomcat-default-login.yaml     # -> 28
```

Anything above 2, or any `attack: clusterbomb` on a login form, does not get run.

## The mandatory verification pass

**No nuclei line becomes a lead until it has been re-proved by hand.** The
template tells you where to look; you produce the evidence.

For every hit:

1. **Re-issue the request yourself** with `curl`, from the template's
   `curl-command` field (nuclei emits it in the JSONL) or from the matching block
   in `fingerprints.md`. If it does not reproduce by hand, it is a false positive
   — delete the line.
2. **Confirm the product independently** via its rung-1 fingerprint, not via the
   template name. `exposed-panels` templates match on titles and favicon hashes
   and confuse similar products routinely.
3. **Check the matcher was not a coincidence.** SPA catch-alls return the same
   200 body on every path, WAF challenge pages return 200 with a challenge body,
   and both light up `exposed-panels`. Fetch a path that cannot exist and compare
   — the same soft-404 discipline `ffuf-web-fuzzing` measures with its baseline.
4. **Re-run the credential yourself, once, from `default-creds.md`** — do not
   accept a `default-login` template's word for it. Capture the request, the
   status, the session field name and the failure body.
5. **Run the product's read-only proof set** (`post-login-proof.md`). A
   `default-login` hit with no admin data read is still N/A.
6. **Capture the negative control** — same endpoint, no session.
7. Only then write the lead, per `../../_shared/references/output-contract.md`,
   with **your** requests and responses in it. The nuclei template id belongs in
   the note as provenance; it must never be the evidence.

Known false-positive shapes worth naming in your note when you kill one: a
`springboot-heapdump` match on a `Content-Length: 0` response; a `default-login`
match where the panel returns 200 for every credential (an SPA that renders the
error client-side); a `grafana-default-login` match on a reverse proxy that
returns a static 200 for `/login`.

Then: `validation`, then `report-writing`.
