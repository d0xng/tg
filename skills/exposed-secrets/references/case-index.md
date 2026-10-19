# Case index — 22 exposed-secret and information-disclosure reports

Every corpus report classified `hardcoded-creds`, `info-disclosure` or `unprotected-creds`, indexed by play, host and outcome. Paths are relative to `~/Desktop/skills/personal-corpus/` — read-only.

Regenerate rows with `python3 scripts/seed_ledger.py`; re-extract bodies with
`python3 scripts/corpus_extract.py '^(info-disclosure|hardcoded-creds|unprotected-creds)$'`.

**Severity:** 4 Critical · 2 High · 11 Medium · P1 · P2 · P3 · P4 · PNone
**State:** **8 duplicate** · **5 informative** · 4 triaged · 2 unresolved · 2 resolved · 1 not-applicable

**This class has the worst conversion rate in the corpus.** 13 of 22 came back duplicate or informative. Leaked keys are the first thing every hunter greps for; read the "did not convert" section before spending a turn.

---

## Saturated hosts

| host | reports | note |
|---|---|---|
| `mee6.xyz` | 2 | both informative — a feature-flag key and CMS tokens, read-only content |
| `*.mercadopago.*` | 2 | one duplicate, one triaged; different plays (inlined config, serialized error) |

Low saturation, but the *class* is saturated rather than the hosts. Check `ledger/reported.md` for the primitive, not only the host.

---

## By play

### 1 · Marketing-platform key holding the customer record

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3763293 | com.public.app.development | **critical** | resolved | `h1/reports/3763293-public-resolved.md` — the model report of this class |

### 2 · Cloud tenant credentials

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3583718 | *.costco.com | **critical** | duplicate | `h1/reports/3583718-costco-duplicate.md` |

### 3 · Serialized error object

| ref | host | sev | state | file |
|---|---|---|---|---|
| 9e1112b24414 | *.quidco.com | **P1** | triaged | `bugcrowd/reports/9e1112b2441448a3a0c2bd2eafdb7ec1-exposed-server-side-credentials-on-accepty-loan-platfor.md` — 4,043 loan records |
| 3861921 | *.mercadopago.com.mx | medium | triaged | `h1/reports/3861921-mercadolibre-elite-triaged.md` — process-wide agent state, 8 identities |

### 4 · Unauthenticated datastore behind a CMS

| ref | host | sev | state | file |
|---|---|---|---|---|
| 9a1beb3359b6 | *.united.com | P2 | unresolved | `bugcrowd/reports/9a1beb3359b6461496f8a8e79869b219-unauthenticated-elasticsearch-exposes-20-production-cre.md` |

### 5 · Capability tokens in public archives

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3899152 | *.trip.com | **critical** | duplicate | `h1/reports/3899152-trip-com-duplicate.md` — 236 distinct archived tokens |

### 6 · Third-party keys — converted

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3907161 | photoshop.adobe.com | **critical** | triaged | `h1/reports/3907161-adobe-triaged.md` — published OAuth token, anonymous delete |
| 3632004 | www.westernunion.com | medium | duplicate | `h1/reports/3632004-western_union-duplicate.md` — links on the brand's own domain |
| 3438542 | *.vectra.ai | medium | duplicate | `h1/reports/3438542-vectra_ai_vdp-duplicate.md` — CMS delivery token |

### 7 · Application serializing its own internals

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3857852 | *.mercadopago.com.ar | medium | duplicate | `h1/reports/3857852-mercadolibre-elite-duplicate.md` — 68 internal services, 5 unauthenticated |

### 8 · Disclosure without a secret

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3856000 | www.milanuncios.com | **high** | triaged | `h1/reports/3856000-adevinta-triaged.md` — averaging defeats per-request jitter |
| 3676048 | product api (Notion) | medium | duplicate | `h1/reports/3676048-notion-duplicate.md` — emails from any public page |
| 3890687 | acrobat ai assistant | medium | duplicate | `h1/reports/3890687-adobe-duplicate.md` — prompt injection exfiltrating workspace documents |

### Did not convert

| ref | host | sev | state | why |
|---|---|---|---|---|
| 3513669 | *.capitalone.com | high | **informative** | payment PII in `GET` parameters, 4 real customers, >$10,900 — still informative |
| 3338578 | gitlab.com | medium | **informative** | admin permission and audit-event enumeration — reconnaissance value only |
| 3661318 | mee6.xyz | medium | **informative** | feature-flag key — business data, no user data |
| 3663259 | mee6.xyz | medium | **informative** | CMS tokens — 11 unpublished drafts, read-only, ordinary content |
| 3451619 | (no asset recorded) | medium | **informative** | header-reflection disclosure |
| 3444834 | *.browserstack.com | medium | duplicate | analytics ingest key — cost inflation and dashboard pollution, no data |
| 116ada51a9cc | *.afterpay.com | P4 | unresolved | credentials in a bundle opening a **sandbox** portal |
| 4a80967c30ad | csscoperations.com | PNone | **not_applicable** | a sensitive document at a public URL. No control was bypassed |
| 815763ba0075 | nasa.gov | P3 | resolved | inconsistent redaction across one archive — the **comparison** is what made it a defect |

---

## What the outcomes teach

**The dividing question is never "is this secret."** It is whether the key reads data, mints compute, or writes to something someone trusts. Sort the corpus by that and the outcomes line up almost perfectly:

- reads customer records → Critical (marketing platform, cloud tenant, archived payment tokens)
- writes or deletes real records → Critical (the survey token, anonymous delete)
- writes into something *trusted* → Medium and worth it (links on the brand's own short domain)
- writes into analytics → duplicate
- reads ordinary content → informative

**Two Criticals were duplicates anyway.** Being right is not enough in this class. Grep `ledger/reported.md` and the corpus index for the primitive **and** for the vendor before starting.

**The chained findings outperform the found ones.** Every top-tier result here needed a second step: the key was in a config file *inside* an unauthenticated search index; the credential was *inside* a serialized error object; the token was *inside* an archived URL. What everyone finds by grepping bundles came back duplicate or informative.

**A public file is not a finding.** The one not-applicable is a genuinely sensitive document at a public URL with no access control bypassed. The comparable report that *did* resolve proved an inconsistency — most documents in the same archive are redacted, two are not. Find the control that failed, or find the sibling that works.
