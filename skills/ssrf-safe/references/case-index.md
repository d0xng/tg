# Case index — 16 SSRF reports

Every corpus report classified `ssrf`, indexed by play, host and outcome. Paths are relative to `~/Desktop/skills/personal-corpus/` — read-only.

Regenerate rows with `python3 scripts/seed_ledger.py`; re-extract bodies with `python3 scripts/corpus_extract.py '^ssrf$'`.

**Severity:** 11 Medium · 4 High · 1 P3 — **no Criticals in this class**
**State:** 7 triaged · 3 informative · 2 duplicate · 2 new · 1 resolved · 1 informational

---

## Saturated hosts

| host | ssrf reports | note |
|---|---|---|
| `firefly.adobe.com` | 3 | three different sinks: an assistant tool, an agentic workflow action, a generation pipeline |
| `*.acrobat.adobe.com` | 2 | the PDF renderer and the certificate validator |
| `abercrombie.com` | 2 | protocol-relative host replacement, and path traversal into a fixed host |
| `other` (Adobe, host not recorded) | 3 | two MCP servers and a chat-completions API |

**Eleven of sixteen are one estate.** Before spending a turn on an Adobe AI surface, read the whole of this index — three of those reports go out of their way to enumerate the sibling reports they are *not* duplicating, which is a good model to follow and a warning about how crowded that surface is.

---

## By play

### 1 · AI tool sink

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3764640 | other (AEM MCP) | **high** | triaged | `h1/reports/3764640-adobe-triaged.md` — exfiltrates the caller's bearer |
| 3743869 | firefly.adobe.com | medium | triaged | `h1/reports/3743869-adobe-triaged.md` — userinfo bypass, full read |
| 3745673 | firefly.adobe.com | medium | triaged | `h1/reports/3745673-adobe-triaged.md` — IMDS + in-pod loopback |
| 3749657 | other | medium | triaged | `h1/reports/3749657-adobe-triaged.md` — k8s API + IMDS |
| 3896569 | other | medium | new | `h1/reports/3896569-adobe-new.md` — MCP tools, persists the body |

### 2 · Renderer that returns the render

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3794880 | *.acrobat.adobe.com | high | **informative** | `h1/reports/3794880-adobe-informative.md` |

### 3 · Protocol-relative URL replaces the host

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3896313 | abercrombie.com | high | duplicate | `h1/reports/3896313-abercrombie-fitch-bbp-duplicate.md` |

### 4 · Path traversal into a fixed internal host

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3896906 | abercrombie.com | medium | new | `h1/reports/3896906-abercrombie-fitch-bbp-new.md` |

### 5 · Document carrying its own URLs

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3791331 | *.acrobat.adobe.com | medium | resolved | `h1/reports/3791331-adobe-resolved.md` — CRL DP + OCSP, unauthenticated |

### 6 · Connection tester

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3867160 | *.mercadopago.com.ar | medium | duplicate | `h1/reports/3867160-mercadolibre-elite-duplicate.md` |
| 3741039 | apps.goshippo.com | medium | **informative** | `h1/reports/3741039-shippo-bbp-informative.md` |

### 7 · Unauthenticated form relay

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3856592 | www.mercadolibre.com.ar | medium | triaged | `h1/reports/3856592-mercadolibre-elite-triaged.md` |

### 8 · The unvalidated sibling parameter

| ref | host | sev | state | file |
|---|---|---|---|---|
| ac6c76dc7bd2 | axis os | P3 | **informational** | `bugcrowd/reports/ac6c76dc7bd2498aa8dc3dbf03f8891f-ssrf-via-proxyaddress-parameter-in-httptest-cgi-localho.md` |

### 9 · Media pipeline fetching an external asset reference

> The image or video processing API accepts an external `href`/`src` and fetches it server-side to work on it. The fetch is the sink; the processing result is irrelevant.

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3753852 | *.lightroom.adobe.com | medium | triaged | `h1/reports/3753852-adobe-triaged.md` — external `href` on an image-processing call; **timing oracle** (instant NXDOMAIN vs 60-second hang against firewalled internal load balancers) plus distinct client error strings for DNS / TLS / refused / timeout. Reachable with a free account and a published api key |
| 3614213 | *.giphy.com | high | **informative** | `h1/reports/3614213-shutterstock-informative.md` — decimal-IP defeats the denylist; port scan + OOB with internal headers |

### Bypass-only, no dedicated play

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3807464 | firefly.adobe.com | medium | triaged | `h1/reports/3807464-adobe-triaged.md` — status-code oracle, k8s API + IMDS `200` on the IAM path |

---

## What the outcomes teach

**This class produces Mediums.** Eleven of sixteen. That is not a failure rate — it is the honest ceiling for a primitive whose impact is reachability. Budget the turn accordingly: an SSRF is worth confirming quickly and worth escalating only where a response body or a credential is in reach.

**All four `informative`/`informational` results are oracle-only or refusal-only.** A port scan, a status differential, a proxy error page. Every one of them proved the fetch happened and none of them brought back an internal document. **The line between Medium and informative in this corpus is whether a named internal resource was retrieved.**

**The single High that is not a duplicate leaked a credential.** The MCP tool that attached the caller's bearer to the outbound request. Everything else at High either read stored credential material out of an internal service or was closed as a duplicate.

**Nobody in this corpus got credentials out of a metadata endpoint.** Two reports reached IMDS; one got `200` on the IAM credentials path through a blind oracle and stated plainly that the role name was not extractable that way. Both were triaged rather than discarded, because they named the remaining barrier instead of implying it was gone.

**Three reports pre-empt their own duplicate closure** by listing the sibling SSRF reports on the same estate and naming the difference — a different service, a different runtime, a different egress region, a different root cause. On a crowded surface, that paragraph is the difference between triaged and duplicate.
