# Panel fingerprints — the unauthenticated request, what it returns, where the version lives

Every request on this page is **rung 1**: unauthenticated, read-only, and never a
finding on its own. Its job is to name the product so `default-creds.md` can tell
you whether a documented default exists, and to pull the build so the verified
CVE map at the bottom can tell you whether `rce-hunting` should take over.

**Use `curl -sD - -o /dev/null <url>`, not `curl -I`.** A `HEAD` request is
answered by fewer panels than you would expect — a bare Python/uvicorn/Werkzeug
management endpoint returns `501 Unsupported method ('HEAD')` and you lose the
header fingerprint you came for. `-sD -` performs a normal `GET` and dumps the
response headers, so the same command works everywhere. Add `-k` for the
appliances, which almost always carry a self-signed or expired certificate.

Set `H` once per host:

```bash
H=https://panel.<target>
```

## Web and ops panels

| Product | Unauthenticated fingerprint request | What comes back | Version path |
|---|---|---|---|
| **Grafana** | `curl -s "$H/api/health"` | `{"commit":"…","database":"ok","version":"9.3.2"}` | `.version` (unauthenticated by design) |
| **Jenkins** | `curl -sD - -o /dev/null "$H/login"` | `X-Jenkins: 2.401.1`, `X-Jenkins-Session`, `X-Hudson`, body `Sign in [Jenkins]` | `X-Jenkins` header |
| **Kibana** | `curl -s "$H/api/status"` | `{"name":"kibana-prod-0","version":{"number":"7.10.2"},"status":{"overall":{"level":"available"}}}` | `.version.number` |
| **Elasticsearch** | `curl -s "$H/"` | `{"cluster_name":"prod-logs","version":{"number":"7.10.2"},"tagline":"You Know, for Search"}` | `.version.number` |
| **Spring Boot** | `curl -s "$H/actuator"` | `_links` index; `Content-Type: application/vnd.spring-boot.actuator.v3+json` | `/actuator/info`, or the JVM/app props in `/actuator/env` |
| **Airflow** | `curl -s "$H/api/v1/version"` | `{"git_version":".release:2.5.1","version":"2.5.1"}` | `.version` (unauthenticated) |
| **Consul** | `curl -s "$H/v1/agent/self"` | `{"Config":{"Datacenter":"dc1","Version":"1.14.4","Server":true}}` | `.Config.Version` |
| **Prometheus** | `curl -s "$H/api/v1/status/buildinfo"` | `{"status":"success","data":{"version":"2.42.0","revision":"225c61"}}` | `.data.version` |
| **RabbitMQ** | `curl -sD - -o /dev/null "$H/api/overview"` | `401` + `WWW-Authenticate: Basic realm="RabbitMQ Management"` | `.rabbitmq_version` — post-auth only |
| **Keycloak** | `curl -s "$H/realms/master/.well-known/openid-configuration"` | `issuer`, `token_endpoint`, `grant_types_supported` incl. `password` | not disclosed unauthenticated; the realm list is |
| **phpMyAdmin** | `curl -sD - "$H/phpmyadmin/" -o pma.html` | `Set-Cookie: phpMyAdmin=…`, `themes/pmahomme/` in the body | `curl -s "$H/phpmyadmin/doc/html/index.html" \| grep -oE 'phpMyAdmin [0-9.]+'` |
| **Adminer** | `curl -s "$H/adminer.php"` | `<title>Login - Adminer</title>`, footer `class="version">4.8.1` | the footer `version` span |
| **Zabbix** | JSON-RPC below | `{"jsonrpc":"2.0","result":"6.0.13","id":1}` | `.result` — **explicitly unauthenticated** per Zabbix docs |
| **Nagios** | `curl -sD - -o /dev/null "$H/nagios/"` | `401` + `WWW-Authenticate: Basic realm="Nagios Access"` | post-auth banner (`Nagios Core … Version 4.4.6`) |
| **Portainer** | `curl -s "$H/api/system/status"` | `{"Version":"2.16.2","InstanceID":"…"}` (older builds: `/api/status`) | `.Version` |
| **MinIO** | `curl -sD - -o /dev/null "$H/minio/health/live"` | `200`, `Server: MinIO`, `x-amz-request-id`, `x-minio-deployment-id` | not in the header; console login page carries it |

### Zabbix — the unauthenticated version RPC

`apiinfo.version` is the one Zabbix API method documented as available to
unauthenticated users, which makes it a clean rung-1 version oracle and a
product confirmation in a single request:

```bash
curl -s -X POST "$H/zabbix/api_jsonrpc.php" -H 'Content-Type: application/json-rpc' \
  -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":[],"id":1}' | jq -r '.result'
# -> 6.0.13
```

Any other method without a session returns the denial, which doubles as your
negative control:

```bash
curl -s -X POST "$H/zabbix/api_jsonrpc.php" -H 'Content-Type: application/json-rpc' \
  -d '{"jsonrpc":"2.0","method":"host.get","params":{},"id":1}' | jq -r '.error.data'
# -> Not authorised.
```

### Spring Boot — the two endpoints that matter

`/actuator/env` and `/actuator/heapdump` are not a credential bug; they are a
**data exposure**, and the moment either answers, the owner is `exposed-secrets`.
Confirm them, then hand off:

```bash
curl -s "$H/actuator" | jq -r '._links | keys[]'
# -> env, health, heapdump, mappings, self

curl -s "$H/actuator/env" | jq -r '.propertySources[].properties | keys[]'
# -> AWS_SECRET_ACCESS_KEY, JAVA_HOME, SPRING_DATASOURCE_PASSWORD

curl -s "$H/actuator/heapdump" -o hd.hprof -w 'bytes=%{size_download}\n'
head -c 18 hd.hprof   # -> JAVA PROFILE 1.0.2
file hd.hprof         # -> Java HPROF dump
```

Spring masks values in `/actuator/env` as `******` by default, so the env dump
usually proves only *which* secrets exist. The **heapdump is the one that
carries the plaintext** — it is a full JVM memory image containing environment
values, in-flight HTTP requests and session tokens. Keep it in
`targets/<program>/notes/`, never in a lead or report, and flag every credential
it yields for rotation. `ffuf-web-fuzzing` finds these paths;
`../../exposed-secrets/references/artifacts-config.md` owns mining them.

### Portainer — the uninitialized-admin state

```bash
curl -s -w ' <- HTTP %{http_code}\n' "$H/api/users/admin/check"
# 404 + {"message": "No administrator account found inside the database", …}
```

A `404` with that message means **no administrator exists yet**: anyone who
reaches this endpoint can claim the instance by POSTing to
`/api/users/admin/init`. That claim is a **write that seizes the deployment and
denies it to its owner — rung 5 — not attempted: ask d0x directly before executing.** The reportable rung-1 fact
is the reachable uninitialized state plus the `204`-vs-`404` differential (`204`
means an admin already exists and there is nothing here).

### Jenkins — no default credential, so read instead

Jenkins ships no default login; the setup wizard prints a random
`initialAdminPassword`. The finding on a Jenkins instance is therefore **anonymous
read**, not a credential:

```bash
curl -sD - -o /dev/null "$H/login" | grep -iE '^(HTTP|X-Jenkins|X-Hudson)'
curl -s "$H/whoAmI/api/json" | jq -c .
# -> {"authenticated":true,"authorities":["authenticated"],"name":"admin"}  = anonymous is authenticated
curl -s "$H/api/json" | jq -c '{mode, useSecurity, jobs:[.jobs[].name]}'
# -> {"mode":"NORMAL","useSecurity":true,"jobs":["deploy-prod"]}
```

`"useSecurity": false`, or a `whoAmI` that returns an authenticated principal for
an unauthenticated request, is the real bug — job names, build logs and
credentials-plugin ids follow. `/script` (the Groovy console) reachable from that
state is straight RCE: hand to `rce-hunting`, do not execute anything yourself
beyond confirming the console renders.

## Edge appliances and mail — mostly fingerprint-only, and that is the point

Card 04's own evidence: the Exchange submission that stopped at
`X-OWA-Version` closed **N/A**. These rows exist so you can *identify* the
appliance and route it, not so you can report the banner.

| Product | Fingerprint request | What comes back | Version path |
|---|---|---|---|
| **Citrix NetScaler / Gateway** | `curl -skD - "$H/vpn/index.html" -o /dev/null` | `Set-Cookie: NSC_TEMP=…` (also `NSC_AAAC`, `NSC_PERS`), `<title>Citrix Gateway` | not disclosed by the gateway vhost; `/logon/LogonPoint/index.html` is the same appliance |

**On a NetScaler configured as a SAML SP, probe `/cgi/logout` before you leave.** The
`RelayState` parameter has a CRLF/response-splitting history there (CVE-2025-12101), the
logout leg needs no valid assertion, and a reflected execution is a finding on its own
merits without any version claim —
`../../auth-flow-bypass/references/saml-xsw.md` §E.
| **PAN-OS GlobalProtect** | `curl -skD - -o /dev/null "$H/global-protect/login.esp"` | `200`, `Set-Cookie: PHPSESSID=…`, `<title>GlobalProtect Portal` | `POST /ssl-vpn/getconfig.esp` returns the portal config XML |

**`/ssl-vpn/getconfig.esp` is also a reflection sink, not only a version oracle.** Its
`user` parameter reflects unsanitised into the response on unpatched PAN-OS
(CVE-2025-0133) — unauthenticated, on a corporate VPN portal, which is about as trusted an
origin as a phishing page can ask for. Probe it while you are already there; a fired
payload is a finding where the banner is not.
`../../xss/references/payloads.md` owns the payloads.
Corpus case: `3710004` — `h1/reports/3710004-x-new.md`.
| **Ivanti / Pulse Connect Secure** | `curl -sk "$H/dana-na/nc/nc_gina_ver.txt"` | `<PARAM NAME="ProductVersion" VALUE="9.1.18.1234">` | that `ProductVersion` attribute |
| **Exchange / OWA** | `curl -skD - -o /dev/null "$H/owa/"` | `X-OWA-Version: 15.2.1544.4`, `X-FEServer: EX01-CORP`, `X-AspNet-Version` | `X-OWA-Version`, and the exact build below |

```bash
# Ivanti / Pulse — version without authentication
curl -sk "$H/dana-na/nc/nc_gina_ver.txt" | grep -oE 'ProductVersion" VALUE="[0-9.]+'

# Exchange — exact build from the eDiscovery export-tool manifest (unauthenticated)
curl -sk "$H/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application" \
  | sed -n 's/.*assemblyIdentity.*version="\([0-9.]*\)".*/\1/p'
# -> 15.2.1544.4
```

Match the manifest version, not the XML declaration — a bare
`grep -oE 'version="[0-9.]+"'` also matches `version="1.0"` from
`<?xml version="1.0"?>` and hands you a nonsense build number.

### The NTLM challenge oracle — an unauthenticated read of the internal AD names

Any endpoint that speaks **Windows integrated auth over HTTP** answers an
unauthenticated NTLM *negotiate* with a *challenge* whose target-info block spells
out the internal Active Directory naming. No credential is sent, nothing is
guessed, and the server volunteers it. This is not Exchange-specific — it applies
to IIS with Windows auth, SharePoint, ADFS, RD Web Access and any reverse-proxied
`/EWS`, `/rpc`, `/mapi`, `/autodiscover`, `/Microsoft-Server-ActiveSync`.

```bash
# one fixed Type 1 blob, reusable verbatim against any of them
NEG='TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=='
curl -sk --http1.1 -D - -o /dev/null "$H/EWS/Exchange.asmx" -H "Authorization: NTLM $NEG" \
  | grep -i '^www-authenticate'
# -> WWW-Authenticate: NTLM TlRMTVNTUAACAAAA…   <- the Type 2, decode it
```

```python
# decode the Type 2 — verified against a spec-shaped message before shipping
import base64, struct
AV={1:'NetBIOS computer',2:'NetBIOS domain',3:'DNS computer (FQDN)',4:'DNS domain',5:'DNS forest'}
def parse(b64):
    d=base64.b64decode(b64)
    assert d[:8]==b'NTLMSSP\x00' and struct.unpack('<I',d[8:12])[0]==2, 'not a Type 2'
    ln,_,off=struct.unpack('<HHI',d[40:48]); p=off; out={}
    v=d[48:56]
    if any(v): out['OS build']=f"{v[0]}.{v[1]}.{struct.unpack('<H',v[2:4])[0]}"
    while p<off+ln:
        i,l=struct.unpack('<HH',d[p:p+4]); p+=4
        if i==0: break
        if i in AV: out[AV[i]]=d[p:p+l].decode('utf-16le')
        p+=l
    return out
# -> {'OS build':'10.0.19041','NetBIOS domain':'WGM','NetBIOS computer':'SRV05',
#     'DNS domain':'wgm.intern','DNS computer (FQDN)':'SRV05.wgm.intern', …}
```

The OS build comes from the version field and is often a **more precise patch
level than the product banner** — it is the Windows build, so it survives a
stripped `Server:` header.

**Fan the same probe across the virtual directories, and compare the answers.**
Auth policy is configured per-vdir, so one host commonly hardens some and not
others — `/mapi/emsmdb/` replying `Negotiate` only while `/EWS/Exchange.asmx`
still replies `NTLM` is a half-finished hardening, and the differential is the
observation worth writing down. `WWW-Authenticate: Negotiate` alone means NTLM is
off on that path; `NTLM` present means it is not.

**What this is worth, stated honestly:** rung 1. The corpus submission that
decoded the topology *and* matched an unpatched build *and* showed the per-vdir
gap still closed **not applicable** — because a relay was never executed, and
executing one is out of the question here (it needs a coerced victim
authentication, which is someone else's credential). Treat the decode as internal
hostnames for the rest of the hunt — names to feed `ssrf-safe`, vhost candidates
for `ffuf-web-fuzzing`, a domain for `exposed-secrets` correlation — not as a
report. The same rule as the version banner, one rung up.

**Corpus case:** `b645a7ab6eae4629911fb4468bf9ef0d` —
`bugcrowd/reports/b645a7ab6eae4629911fb4468bf9ef0d-exchange-2019-unpatched-ntlm-relay-cve-2024-21410-basic.md`
(P3 · not applicable · not a duplicate — the outcome is the lesson).

**Where the appliance defaults actually apply.** `nsroot:nsroot` (NetScaler) and
`admin:admin` (PAN-OS) are **management-plane** credentials — they belong to the
NSIP/management interface, not to the user-facing VPN portal you just
fingerprinted. Unless the program handed you the management interface as an
in-scope asset, the portal fingerprint is where this stops. Say so in the note
and rotate; do not send management credentials at a gateway vhost that will never
accept them.

## Version → verified CVE map

Every id below was pulled from its NVD record during authoring, with the affected
and fixed ranges quoted from that record **except where the row names the vendor
advisory as its source** — NVD does not carry build numbers for every id (the
Exchange row below is one such case). **Matching a version here is still a
fingerprint** — card 04's verdict stands: fingerprint-only CVE claims close
informative or N/A. This map exists to tell you when to hand the host to
`rce-hunting`, which owns exploitation.

| Product / range | CVE | Class | Fixed in |
|---|---|---|---|
| Jenkins ≤ 2.441, LTS ≤ 2.426.2 | **CVE-2024-23897** | CLI arg parser expands `@<path>` → unauthenticated arbitrary file read on the controller | 2.442, LTS 2.426.3 |
| Grafana 8.0.0-beta1–8.3.0 (except patched) | **CVE-2021-43798** | directory traversal via `<host>/public/plugins/<plugin-id>/` → local file read | 8.0.7 / 8.1.8 / 8.2.7 / 8.3.1 |
| NetScaler ADC & Gateway 13.0 < 13.0-92.19, 13.1 < 13.1-49.15, 14.1 < 14.1-8.50 (also 12.1-FIPS/NDcPP < 12.1-55.300, 13.1-FIPS < 13.1-37.164) | **CVE-2023-4966** | sensitive information disclosure when configured as Gateway (VPN vserver / ICA Proxy / CVPN / RDP Proxy) or AAA vserver — session-token leak | the versions listed |
| PAN-OS < 10.2.9-h1, < 11.0.4-h1, < 11.1.2-h3 with GlobalProtect | **CVE-2024-3400** | command injection via arbitrary file creation → unauthenticated root code execution | 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 |
| Ivanti Connect Secure 9.x, 22.x; Policy Secure 9.x, 22.x | **CVE-2023-46805** (auth bypass, CWE-287) chained with **CVE-2024-21887** (authenticated command injection, CWE-77) | the pair yields unauthenticated command execution | per Ivanti's advisory matrix |
| Exchange 2016 CU23 < 15.01.2507.037; Exchange 2019 CU13/CU14 < 15.2.1544.004 (**builds per Microsoft's advisory — NVD carries only CU-level CPEs**) | **CVE-2024-21410** | elevation of privilege — NTLM relay to Exchange where Extended Protection is off | 15.01.2507.037 / 15.02.1544.004 |

Note on the Exchange row (source: **Microsoft, not NVD**): card 04 records the
boundary build as `15.2.1544.9`. NVD's record for CVE-2024-21410 carries no build
numbers at all — its description is the one-line "Microsoft Exchange Server
Elevation of Privilege Vulnerability" and its CPEs are CU-level only
(`exchange_server:2016:cumulative_update_23`, `2019:cumulative_update_13`,
`2019:cumulative_update_14`). **Microsoft's advisory** pins the fix at Exchange
2019 CU14 / build `15.02.1544.004` (the release that enables Extended Protection
by default) and Exchange 2016 CU23 Feb24SU / `15.01.2507.037`. So a host
reporting `X-OWA-Version: 15.2.1544.4` is **already patched** — use the Microsoft
build number, and cite Microsoft (not NVD) if the build appears in a report.

Nothing here is a report on its own. A matched range plus an actual proof
(the file read, the leaked session token, the executed command) belongs to
`rce-hunting`; a matched range on its own belongs in `notes/`.

**Check the other preconditions anyway — they are free, and they are what you write in
`notes/`.** A version match is one of several conditions; confirming the rest costs
nothing and is still rung 1. The protocol-level one is the most commonly skipped:

```bash
# is the vulnerable protocol/module actually negotiated?
python3 -c "import ssl,socket,sys
h=sys.argv[1]; c=ssl.create_default_context(); c.set_alpn_protocols(['h2','http/1.1'])
s=c.wrap_socket(socket.socket(), server_hostname=h); s.connect((h,443))
print('ALPN ->', s.selected_alpn_protocol())" "$HOST"
curl -skI --http2 "https://$HOST/" | head -1        # HTTP/2 <status> = h2 served
```

**And when the exploit is a crash, do not run it.** A memory-corruption or resource
-exhaustion PoC against production is a service-degradation action — rung 5, never
attempted, regardless of how confident the version match is. State the reachability and
stop.

**The outcome to expect, from the corpus:** the same Apache HTTP/2 memory-corruption CVE
was submitted against three separate hosts with correct version fingerprinting, correct
protocol confirmation, and an explicit and correct refusal to fire the DoS. All three
closed **informative / P5**. Refusing to exploit was right; filing it anyway was not.
Route a fingerprint-only match to `notes/` and spend the turn elsewhere.

**Corpus cases:** `3718926` — `h1/reports/3718926-grab-informative.md`; `3718949` —
`h1/reports/3718949-adobe-informative.md`; `f22622a3abb546a889a3462ff7595e87` —
`bugcrowd/reports/f22622a3abb546a889a3462ff7595e87-cve-2026-23918-apache-http-2-double-free-dos-rce-on-cpp.md`.
