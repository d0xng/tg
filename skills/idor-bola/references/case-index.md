# Case index — 18 IDOR / BOLA reports

Every corpus report classified `idor`, indexed by play, host and outcome. Paths are relative to `~/Desktop/skills/personal-corpus/` — read-only, never written to.

Regenerate the underlying rows with `python3 scripts/seed_ledger.py`; re-extract the report bodies with `python3 scripts/corpus_extract.py '^idor$'`.

**Severity:** 5 High · 3 Critical · 3 Low · 2 Medium · 2 P2 · 3 P3
**State:** 4 triaged · 3 unresolved · 3 resolved · 3 duplicate · 2 not-applicable · 1 retesting · 1 new · 1 pending

---

## Saturated hosts — check before spending a turn

| host | idor reports | note |
|---|---|---|
| `*.theory.com` | 2 | the same vendor API twice; the second is the sequential-uid escalation of the first |
| `firefly.adobe.com` | 2 | read (Low) and write (High) of the same org-header defect |

Small numbers here, unlike `broken-access-control` where two Adobe hosts carry eleven reports between them. **The IDOR corpus is broad rather than deep** — 18 reports across 16 distinct hosts — which is what a repeatedly-converting technique looks like. Check `ledger/reported.md` for the full picture across classes before assuming a host is fresh.

---

## By play

### 1 · Vendor preference API — credentials in the page, no authorization behind them

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3481692 | *.theory.com | **critical** | triaged | `h1/reports/3481692-fast_retailing-triaged.md` |
| 3819989 | *.theory.com | **critical** | retesting | `h1/reports/3819989-fast-retailing-retesting.md` — sequential-uid escalation of the above |
| 3487578 | *.epicgames.com | high | resolved | `h1/reports/3487578-epicgames-resolved.md` |
| 75e46a2608ab | *.assurancewireless.com | P3 | unresolved | `bugcrowd/reports/75e46a2608ab4379a3c359bd266a46e8-api-credentials-exposure-in-client-side-code-allows-una.md` |

### 2 · RPC proxy drops the session

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3897811 | *.trip.com | **critical** | new | `h1/reports/3897811-trip-com-new.md` |

### 3 · Path authorizes one segment, fetches by another

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3851866 | www.coches.net | medium | triaged | `h1/reports/3851866-adevinta-triaged.md` |

### 4 · Body identity field not bound to the token

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3793330 | new.express.adobe.com | medium | duplicate | `h1/reports/3793330-adobe-duplicate.md` — read |
| 3744810 | express ai assistant | low | resolved | `h1/reports/3744810-adobe-resolved.md` — write-only |
| 3755067 | photos.adobe.io | low | resolved | `h1/reports/3755067-adobe-resolved.md` — write-only |

### 5 · Client-supplied impersonation headers

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3859466 | *.mercadopago.com.mx | high | duplicate | `h1/reports/3859466-mercadolibre-elite-duplicate.md` |

### 6 · Org header as a routing hint

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3807587 | firefly.adobe.com | high | triaged | `h1/reports/3807587-adobe-triaged.md` — write twin |
| 3749587 | firefly.adobe.com | low | triaged | `h1/reports/3749587-adobe-triaged.md` — read |

### 7 · Unauthenticated write on a sequential id

| ref | host | sev | state | file |
|---|---|---|---|---|
| 83aafc730520 | *.wien.gv.at | P2 | unresolved | `bugcrowd/reports/83aafc7305204674ab238fdd4c33abd6-unauthenticated-mass-record-takeover-on-stp-wien-gv-at.md` |

### 8 · Credentials plus a chain

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3770014 | app.loadninja.com | high | pending | `h1/reports/3770014-smartbear-software-bbp-pending-program-review.md` |
| 62e829849e92 | saudia android app | P3 | unresolved | `bugcrowd/reports/62e829849e9245b09b5b1a4f75fd41fe-authentication-bypass-chain-via-exposed-azure-ad-creden.md` |

### 9 · Unauthenticated staging instance

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3617605 | *.huffpost.com | high | duplicate | `h1/reports/3617605-buzzfeed-duplicate.md` |

### Did not convert

| ref | host | sev | state | why |
|---|---|---|---|---|
| 27f3e6774897 | haiku-qa | P2 | **not_applicable** | viewer role could rename a team. Clean proof — every sibling operation returned `403`, the source map defined the intent — but the object was cosmetic settings and no data crossed a boundary |
| d27402e38e53 | orders (accesso) | P3 | **not_applicable** | full read/modify/cancel of any basket by UUID, but on a `.stg.` host reached through a forwarded-header bypass. Staging with synthetic data caps the impact |

---

## What the outcomes teach

**Rank by object sensitivity before spending the turn.** Both non-applicable results proved the authorization defect cleanly and failed on what the object carried — a team name, a staging basket. The three Low results are the same story in a different direction: the check was genuinely missing, and the endpoint was write-only, so nothing could be read back.

**The three Criticals share one property, and it is not the bug.** Trip.com, and both Theory reports: in every case the identifier needed was **published somewhere anonymous** — a public profile feed, a sequential counter, a rendered preference page. The authorization gap was ordinary; what made it Critical was that victim selection was free.

That is the ranking signal. When triaging which lead to dispatch, ask where the identifier comes from before asking how bad the endpoint is.

**The write twin is worth finding.** Two pairs in this corpus show the same defect scoring Low as a read and High as a write: the org-header pair on one host, and the read/write split on the RPC proxy. When a read IDOR lands, spend one more request looking for the mutating sibling on the same object.
