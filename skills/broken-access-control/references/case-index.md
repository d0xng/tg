# Case index — 29 broken-access-control reports

Every report in the corpus classified under `broken-access-control` or `missing-authz`, indexed by play, host and outcome.

Paths are relative to `~/Desktop/skills/personal-corpus/` — read-only, never written to.

Regenerate the underlying rows with `python3 scripts/seed_ledger.py`.

**Outcomes:** 11 High · 10 Medium · 6 Critical · 2 Bugcrowd (P1, P5)
**States:** 11 new · 8 duplicate · 3 triaged · 3 informative · 2 pending · 1 resolved · 1 informational

---

## Saturated hosts — check before spending a turn

These already carry multiple reports of this exact class. A new finding here needs to be a **different primitive**, not the same one on a new path. Same primitive plus same host is `closed:duplicate` at step 3 of the turn.

| host | BAC reports | note |
|---|---|---|
| `new.express.adobe.com` | **7** | heavily hunted; 4 of the 7 already came back duplicate |
| `firefly.adobe.com` | **4** | 3 of 4 duplicate or resolved |
| `abercrombie.com` | **3** | 1 duplicate, 2 still open |
| Adobe Express AI assistant surface | 2 | both the same DynamoDB proxy; one is a resubmission |

Same technique on a **new host** remains a new finding — that is the play, not the exception. What is dead is the same primitive on a host already in this table.

---

## By play

### 1 · Enforcing sibling

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3909250 | abercrombie.com | high | duplicate | `h1/reports/3909250-abercrombie-fitch-bbp-duplicate.md` |
| 3896657 | abercrombie.com | medium | new | `h1/reports/3896657-abercrombie-fitch-bbp-new.md` |
| 3890078 | new.express.adobe.com | medium | new | `h1/reports/3890078-adobe-new.md` |
| 3753228 | firefly video model | critical | informative | `h1/reports/3753228-adobe-informative.md` |
| 3749634 | firefly.adobe.com | medium | resolved | `h1/reports/3749634-adobe-resolved.md` |

### 2 · Decorative credential

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3842276 | firefly.adobe.com | medium | duplicate | `h1/reports/3842276-adobe-duplicate.md` |
| 3895309 | new.express.adobe.com | medium | new | `h1/reports/3895309-adobe-new.md` |

### 3 · Client-supplied identity header

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3914032 | *.newegg.com | **critical** | new | `h1/reports/3914032-newegg-new.md` |
| 3849806 | milanuncios (no asset recorded) | medium | pending | `h1/reports/3849806-adevinta-pending-program-review.md` |

### 4 · Unauthenticated CRUD on a backend found in the bundle

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3776894 | express ai assistant | **critical** | duplicate | `h1/reports/3776894-adobe-duplicate.md` |
| 3777402 | express ai assistant | high | informative | `h1/reports/3777402-adobe-informative.md` — resubmission of 3776894 |
| 3791373 | new.express.adobe.com | high | duplicate | `h1/reports/3791373-adobe-duplicate.md` |
| 3895348 | tidyup-dev (no asset recorded) | high | new | `h1/reports/3895348-adobe-new.md` |

### 5 · Object reference with no owner check

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3895298 | abercrombie.com | high | pending | `h1/reports/3895298-abercrombie-fitch-bbp-pending-program-review.md` |
| 3851962 | www.coches.net | high | new | `h1/reports/3851962-adevinta-new.md` |
| 3895191 | new.express.adobe.com | high | duplicate | `h1/reports/3895191-adobe-duplicate.md` |
| 3861742 | *.mercadopago.com.mx | medium | triaged | `h1/reports/3861742-mercadolibre-elite-triaged.md` |
| 3866958 | *.mercadopago.com.ar | medium | duplicate | `h1/reports/3866958-mercadolibre-elite-duplicate.md` |
| 3895140 | *.wolt.com | medium | new | `h1/reports/3895140-wolt-new.md` |
| 3898191 | firefly.adobe.com | medium | duplicate | `h1/reports/3898191-adobe-duplicate.md` |
| 799ae1120d14 | *.united.com | P5 | informational | `bugcrowd/reports/799ae1120d144c31a78ddc724af6b09b-unauthenticated-access-to-united-airlines-crew-consent.md` |

### 6 · Entitlement never checked

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3753228 | firefly video model | critical | **informative** | see play 1 — metering framed as authorization |
| 3749634 | firefly.adobe.com | medium | resolved | see play 1 |

### 7 · Allowlist regex not anchored

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3909155 | new.express.adobe.com | high | triaged | `h1/reports/3909155-adobe-triaged.md` |
| 3909271 | firefly.adobe.com | high | new | `h1/reports/3909271-adobe-new.md` |

### 8 · Origin reachable behind the edge

| ref | host | sev | state | file |
|---|---|---|---|---|
| fde0827c1181 | saudiare.sa | P1 | triaged | `bugcrowd/reports/fde0827c11814b1fae69569d051da06f-broken-access-control-unauthenticated-access-to-all-adm.md` |

### 9 · Gated on state instead of identity

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3849699 | www.milanuncios.com | critical | **informative** | `h1/reports/3849699-adevinta-informative.md` — write inferred, not demonstrated |

### 10 · Server-side relay substituting a secret

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3909187 | new.express.adobe.com | high | new | `h1/reports/3909187-adobe-new.md` |

### Unclassified / single instances

| ref | host | sev | state | what it was |
|---|---|---|---|---|
| 3909216 | ca.preprod.alkira3.net | **critical** | new | step-ca `/1.0/provisioners` unauthenticated → SSO client secrets + CA provisioner keys unredacted. Product-version defect, not a pattern: current step-ca redacts these fields |
| 3802453 | admin.shopify.com | high | new | a read-only staff permission returns full plaintext gift-card codes through the internal admin GraphQL. **Role-scope defect** — the permission exists and grants more than it names |
| 3908333 | new.express.adobe.com | critical | duplicate | encrypted handoff blob whose `pollingUrl` is unvalidated → victim's token sent to attacker host. Close relative of play 7, different mechanism: the passphrase is `SHA256(victim user id)`, and a user id is not a secret |

---

## What the outcomes teach

**The three `informative` results are all the same mistake in different clothes:** the finding was real and the *frame* was wrong.

- 3753228 — metering claimed as authorization
- 3849699 — write inferred rather than demonstrated
- 3777402 — a resubmission

**The eight `duplicate` results cluster on two hosts.** Six of the eight are Adobe Express or Firefly. That is not bad luck; it is a heavily-hunted estate. The dedup step exists for exactly this.

**The six Criticals share one property:** every one of them needed **no credential at all**, or a credential the attacker already holds by default. Nothing in the Critical tier required a privileged role. When triaging which lead to dispatch first, that is the signal — the shortest path to a Critical in this corpus was always "strip the credential and see what answers".
