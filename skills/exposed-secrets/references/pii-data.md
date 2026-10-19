# PII And Sensitive Data Exposure

Use for names, emails, phone numbers, addresses, documents, applicant records,
chat logs, support tickets, medical/financial data, and private user datasets.

## Method

1. Confirm intended access boundary: anonymous, registered user, role, tenant,
   program, customer, or owner.
2. **Prove the class with a minimal cross-boundary read.** Fetch one or two
   records that you are NOT entitled to (an anonymous/low-priv session reading a
   record owned by an account you seeded, or the object exposed by the leaked
   key). One representative cross-boundary read proves the exposure — that IS the
   finding, not a hand-off (safe ladder rungs 2-3).
3. Record field names, record count if visible, one or two redacted sample rows,
   endpoint/path, and access state.
4. **State scale by inference, do not exfiltrate it.** If you can read record N
   you can read N+1 — say so; never mass-enumerate other users' PII to "show
   scale" (nothing blocks it, and the program penalizes it).
5. If RoE restricts PII/cross-tenant testing to UAT/OAT, do the full read there
   and infer prod (safe ladder rung 4). Confirm with `validation` before reporting.

## Good Evidence

- registered/low-privileged/anonymous actor **read** another user's sensitive
  record (one bounded sample, redacted);
- endpoint returns bulk records or search/list data (one page proves it);
- field names show high-impact PII;
- negative control shows the intended UI/role denies the same access.

## Severity Notes

- full names plus email/phone at scale usually high.
- documents, applicant data, medical/financial records, chats, support tickets,
  or credentials may be critical depending on scale and access.
