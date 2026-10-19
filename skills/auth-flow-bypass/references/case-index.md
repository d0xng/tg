# Case index — 6 authentication-bypass reports

Corpus reports classified `auth-bypass`, `auth-rate-limit` or `sig-verification`. Paths are relative to `~/Desktop/skills/personal-corpus/` — read-only.

Regenerate rows with `python3 scripts/seed_ledger.py`; re-extract bodies with
`python3 scripts/corpus_extract.py '^(auth-bypass|auth-rate-limit|sig-verification)$'`.

**State:** 1 triaged · 1 new · 2 unresolved · 1 informative · 1 not-applicable
**Severity:** 2 Critical · 1 Medium · P1 · P3 · P3

A small sample. Its value is that a third of it did not convert and the reasons are precise — see the bottom section before planning a proof.

---

## By play

### 1 · Token-issuing endpoint that validates context, not identity

| ref | host | sev | state | file |
|---|---|---|---|---|
| b58ed2d07183 | *.united.com | P3 | unresolved | `bugcrowd/reports/b58ed2d07183496387bdc7d5ed7214f1-unauthenticated-access-to-production-passenger-pii-via.md` |

### 2 · Self-writable identity-provider attribute

| ref | host | sev | state | file |
|---|---|---|---|---|
| 44c61de21b4e | haiku-qa | P3 | unresolved | `bugcrowd/reports/44c61de21b4e4a1db707c1d64abd3af9-cognito-custom-attribute-manipulation-in-haiku-authenti.md` |

Cross-listed: the same estate appears in `broken-access-control` (`27f3e6774897`, a viewer role that could rename a team) and both reports were found through the same published source map.

### 3 · Unauthenticated oracle extracting the reset token

| ref | host | sev | state | file |
|---|---|---|---|---|
| 17a715008c76 | infiniteathlete.ai | **P1** | new | `bugcrowd/reports/17a715008c764ca283d57e610dbaa52e-unauthenticated-boolean-oracle-in-strapi-cms-allows-sup.md` |

### 4 · Default credentials on an ops panel

| ref | host | sev | state | file |
|---|---|---|---|---|
| 3701766 | staging.uipath.com | **critical** | triaged | `h1/reports/3701766-uipath-triaged.md` |

Route the *panel* discovery through the `infra-panels-default-creds` skill; the session enumeration that earned the severity is the part that belongs here.

### Did not convert

| ref | host | sev | state | why |
|---|---|---|---|---|
| 3714964 | www.vodacom.co.tz | critical | **informative** | OTP brute force: no rate limit, no lockout, 30-minute validity. Arithmetic unarguable; **takeover never demonstrated on a real account** |
| 3810939 | github.com (protocol) | medium | **not-applicable** | signature-counting flaw halving a Byzantine threshold. Correct and deep; **outside what that program buys** |

---

## What the outcomes teach

**Neither failure was technical.** One failed on proof shape, one on venue. Both were avoidable before the turn was spent.

**Plan the last step of the proof onto an account you control.** The OTP finding stops one step short of the impact because the remaining step needs a stranger's phone. Brute-force your own number, complete the takeover on your own account, and state the victim case by inference — that converts the same evidence into a demonstration.

**Check the program's excluded classes at DISPATCH.** The signature-counting report is the strongest piece of pure analysis in the whole corpus and it was filed somewhere that does not pay for it.

**Decode the token before touching the target.** Two of these six turned entirely on what the token itself carried: the identity-provider pool and client ids, and the scope granting self-administration. Zero requests to the target, and it is what made the tenant bypass findable at all.

**A non-production hostname discounts the finding even when the data is production.** The gate-agent tool queried the live reservation system and returned real passengers' contact details; it sat at P3. Budget accordingly, and when the data *is* production, say so in the title.

**Enumerate what the session reaches.** The least technical finding here — a default password — scored Critical because the report counted 649 dashboards, 31 datasources, six staff admin accounts, and named the specific admin operations available, including silently changing the password to lock out the real admins. The bypass opens the report; it does not close it.
