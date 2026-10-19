---
name: sqli
description: "SQL injection hunting — detection (error/boolean/time/union), DBMS fingerprint, blind extraction, CMS-specific pre-auth chains (Drupal CVE-2026-9082, Ghost NQL CVE-2026-26980, Strapi where-oracle CVE-2026-27886), NoSQL injection, and WAF bypass. TRIGGER: a parameter reaches a query (filters, search, sort, id, returnUrl, login JSON), an error leaks SQLSTATE/ORA-/HY093/MySQL-syntax, a CMS with a known SQLi CVE, an x[$ne]= or {\"$ne\":null} operator sink, or user mentions SQLi/blind/boolean/time-based/NoSQLi. Non-destructive: read-only, never DROP/UPDATE/DELETE."
---

# sqli — a reflected param is rung 0; the proven data read / ATO is the finding

An injectable parameter is **not** the finding. A `SQLSTATE` in a 500 is not the
finding. The finding is what you **read out** (an admin hash, a live
password-reset token, a session, one row of schema you were not entitled to) or
the **account you take over** with it. The SQLi chains that convert are
end-to-end: Ghost NQL blind SQLi -> extract the `api_keys` admin secret -> sign
an Admin JWT -> CMS takeover; Strapi `where` oracle -> extract the admin
`resetPasswordToken` -> Super-Admin. Detection is where you start; **extraction
to a payable secret is the deliverable.**

Climb the shared safe ladder (`../_shared/references/safe-ladder.md`): confirm
the oracle read-only -> prove the class on the cheapest non-mutating call -> pull
the **minimum** that proves impact (one admin hash / one row, never the whole
table) -> use UAT if RoE gates cross-tenant/PII proof -> reach the payable
impact. Stopping at "the param is injectable" is the failure this skill kills.

Every payload below is fired from a normal shell — `curl`, `python3` and `sqlmap`
(`sqlmap`, on PATH) are executed directly, not described.

> **Novelty-check before you report — reuse the technique, not a past report.**
> The methodology below is portable; a specific past submission is not a new
> finding. Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

## Read-on-demand references

Keep the trigger map internalized; open the reference when you commit to a class.

- `references/detection-fingerprint.md` — the five detection oracles
  (error / boolean / time / UNION / OOB), how to make each **false-positive
  proof**, and DBMS fingerprinting (dialect, concat, comment, version). Read
  this first on any raw param.
- `references/blind-extraction.md` — turn a confirmed oracle into data:
  char-by-char binary search with `SUBSTRING((subquery),i,1)`, UNION column
  discovery + exfil, `information_schema` targeting, OOB/DNS exfil when stacked,
  and how to hand the exact request to `sqlmap` (`--technique=BT --dbms=…`)
  without letting it write.
- `references/cms-cve-chains.md` — pre-auth CMS chains that convert to Critical. Drupal core CVE-2026-9082 (PostgreSQL-only JSON-key
  breakout, JSON:API fingerprint + login div-by-zero oracle), Ghost
  CVE-2026-26980 (NQL `filter=slug` -> `EXP(710)` overflow oracle -> `api_keys`
  secret -> Admin JWT), Strapi CVE-2026-27886 (`where` -> `meta.pagination.total`
  1-bit oracle -> admin `resetPasswordToken` -> Super-Admin), and the legacy
  `returnUrl` boolean-blind login flow.
- `references/nosql-injection.md` — Mongo/NoSQL operator injection: JSON-body and
  query-string `$ne`/`$gt`/`$regex` auth bypass, `$where`/`$expr` JS injection
  (boolean + time oracle), `$regex` char-by-char blind extraction of a hash /
  reset token -> ATO.
- `references/waf-bypass.md` — when the payload is filtered: comment/case/
  encoding/whitespace/keyword-split/`EXP()`/`||`↔`CONCAT`/JSON-array-key bypasses,
  matched to the parser rather than sprayed.
- `../_shared/references/output-contract.md` — where results go: the notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim` dedup key, and the severity enum.

Also import: `../_shared/references/safe-ladder.md` (how far to climb, and the
timid phrasings to never produce). A hash/token/key you extract via SQLi is then
a secret to *exercise* -> `exposed-secrets` + `../_shared/references/public-by-default-keys.md`.

## §0 — Find the injectable surface (from what d0x already collected)

Grep the JS bundles, captured requests/responses, and HTML for parameters that
plausibly reach a query, and CMS fingerprints:

- **Any param that names a column/table/row**: `id`, `uid`, `orderId`,
  `productId`, `category`, `filter`, `q`/`search`, `sort`, `order`,
  `orderBy`/`order_by`, `groupBy`, `columns`, `limit`/`offset`, `where`. `sort`/
  `order`/`orderBy` are high-yield — they usually can't be parameterized so they land
  in the query as a **string** (`ORDER BY <injectable>`).
- **JSON login/auth bodies** — `{"name":…,"pass":…}`, `{"username":…,"password":…}`.
  Object values are where NoSQL operator injection lives; nested keys are where
  the Drupal PDO-placeholder class lives.
- **`returnUrl`/`return`/`redirect` on legacy .NET/Java login** — a known
  boolean-blind sink; test it as one, not just an open-redirect.
- **CMS generators / paths** — `<meta name="generator" content="Ghost">`,
  `/ghost/api/content/…`; Drupal `X-Generator: Drupal`, `/jsonapi/…`,
  `/user/login?_format=json`; Strapi `cms.<target>`, `/api/<collection>` with a
  `meta.pagination.total`, `/admin/forgot-password`. -> `cms-cve-chains.md`.
- **An error already leaking the DB** in a captured response: `SQLSTATE[...]`,
  `You have an error in your SQL syntax` (MySQL), `ORA-01756` (Oracle),
  `unterminated quoted string`/`HY093` (Postgres/PDO), `SQLite error`,
  `Unclosed quotation mark` (MSSQL). That is a fingerprint AND a confirmed sink —
  go straight to extraction.

## Trigger map — signal -> class -> first move

| You see (signal) | Class | First non-destructive move | Reference |
|---|---|---|---|
| `id`/numeric param, response differs | error/boolean | `'` then `AND 1=1` vs `AND 1=2` differential | `detection-fingerprint.md` |
| `sort`/`order`/`orderBy` param | order-by / stacked-safe | `,(SELECT 1)` vs `,(SELECT 1 UNION SELECT 2)`; CASE in ORDER BY | `detection-fingerprint.md` |
| No error, no boolean diff | time-blind | `' OR SLEEP(5)-- -` / `'||pg_sleep(5)--`; confirm repeatable | `detection-fingerprint.md` |
| `SQLSTATE`/`ORA-`/`HY093` in a 500 | error-based (confirmed) | fingerprint dialect -> go to extraction | `blind-extraction.md` |
| Ghost `<generator>` + Content API key | Ghost NQL SQLi CVE-2026-26980 | `filter=slug:['||CASE WHEN 1=1 THEN 0 ELSE EXP(710) END||',<slug>]` 200=true | `cms-cve-chains.md` |
| Drupal + JSON:API + Postgres | Drupal core SQLi CVE-2026-9082 | backtick in a bracketed filter key -> `HY093` | `cms-cve-chains.md` |
| Strapi `/api/<coll>` + `meta.pagination.total` | Strapi `where` oracle CVE-2026-27886 | `?where[id][$lt]=-1` zeroes `total` | `cms-cve-chains.md` |
| JSON login body / `x[$ne]=` in query | NoSQL / Mongo | `{"password":{"$ne":null}}` auth bypass | `nosql-injection.md` |
| Payload 403'd / keyword blocked | WAF | inline-comment / case / `EXP()` / array-key bypass | `waf-bypass.md` |

## Algorithm

1. **Pick ONE parameter and go deep** (Pivot Triggers: rotate *angles* on the
   same param before dropping it). Classify the context — numeric, string-quoted,
   `ORDER BY`, JSON value, JSON key, NQL, ORM `where`, Mongo operator.
2. **Confirm the oracle read-only, and make it false-positive-proof**
   (`detection-fingerprint.md`). The confirm is a *differential you can repeat*,
   not one 500: boolean `1=1`≠`1=2` stable across re-runs; timing that tracks the
   delay (5s vs 0s vs 10s), not one slow response; a DB-specific error string, not
   a generic 500. A single anomaly is a lead, not a confirm.
3. **Fingerprint the DBMS** — dialect decides the extraction gadget and some bugs
   are DB-specific (Drupal CVE-2026-9082 is **PostgreSQL only**). `@@version` /
   `version()` / `banner`; concat `||` (Postgres/Oracle) vs `CONCAT()` (MySQL);
   comment `-- -` / `#` / `/**/`.
4. **Climb the safe ladder to a payable read** (`blind-extraction.md`):
   - Rung 1 (read-only): prove the oracle reads *something* — a version string, a
     `count`, `current_user`, one byte of a non-secret. That already proves the
     class.
   - Rung 2/3 (minimal, own/anon context): extract the **one** secret that proves
     impact — the admin password hash, a live `resetPasswordToken`, a session
     token, one row of `information_schema` you were not entitled to. **One**, not
     the table. If ids/rows are predictable, one read proves you can read N+1 —
     say so, don't dump.
   - Rung 4 (UAT): if RoE gates PII/cross-tenant proof to `*-uat`/`*-oat`, do the
     full data read there; on prod stop at a non-PII read (version/count/schema
     name) and state the prod-equivalent impact by inference.
   - Rung 5 (writes/other-user/financial on prod): you should never need it —
     SQLi proof is a *read*. If a chain seems to require a write (e.g. actually
     resetting the admin's password after extracting the token), **STOP before the
     write** and report the extracted token as the proof. The write requires d0x's approval before execution.
5. **Convert to the real impact, don't stop at the string.** An extracted admin
   hash -> note crack feasibility / reuse, don't stop at "I have a hash." A Ghost
   `api_keys` secret -> **sign the Admin JWT and read one admin-only object**
   (read-only) to prove takeover. A Strapi `resetPasswordToken` -> demonstrate it
   is valid (its presence + format is the proof); **do not consume it** to change
   the admin password on prod.
6. **Write the proof to disk** — the full re-runnable chain (the oracle, the
   fingerprint, the extracted secret redacted, the negative control) per the
   evidence checklist below and `../_shared/references/output-contract.md` — then
   rotate to the next parameter/CMS surface. Validate any High/Critical with
   `validation` first.

## Evidence to capture (self-contained and re-runnable)

`validation` re-proves the claim, so every proof must be copy-pasteable. Per class:

- **Error/boolean/time**: the confirming **differential** — balanced vs unbalanced,
  `1=1` vs `1=2`, or the 0s/5s/5s timing series (a single 500 is NOT evidence) —
  plus the DB error string that fingerprints the dialect.
- **Extraction**: the char-by-char gadget request, the **redacted** extracted value
  (`hash=$2y$…REDACTED`, `token=9a…REDACTED` — keep format and length so it is still
  provable), and which table/column/uid it came from.
- **Ghost**: the `EXP(710)` 200/500 oracle; the extracted `api_keys` id (secret
  redacted); the forged Admin JWT header/payload; the `GET /ghost/api/admin/…` 200
  proving takeover read-only.
- **Strapi**: the `where[id][$lt]=-1` -> `total:0` oracle; the `$startsWith` walk
  recovering the admin email; the redacted `resetPasswordToken`; an explicit note
  that you STOPPED before `/admin/reset-password`.
- **Drupal**: the `HY093` fingerprint request; the login `SQLSTATE[22012]`
  div-by-zero oracle (true) vs `400` (false); the redacted uid=1 hash.
- **NoSQL**: the `{"$ne":null}` / `{"$gt":""}` body that authenticated without a
  password (and which account it logged into), or the `$regex` differential.

Always include the **negative control** — the request that does NOT trigger
(balanced payload, `1=2`, the patched response shape) — proving the differential is
real and not coincidental. If you found an **enforcing sibling** (a
parameterized/patched endpoint next to the vulnerable one), name it: "sibling X is
parameterized, vulnerable Y concatenates" is a strong convert argument. **Add a
rotation note for every credential/hash/token you extracted.**

Keep the raw, unredacted material — full char-by-char logs, forged-JWT material,
`sqlmap` output — in `targets/<program>/notes/`; redact hashes/tokens/emails in the
lead and the finding, keeping table/column/uid in `id=<n>`/name form so reproduction
and dedup survive.

## Converts? (severity reality — grade honestly)

- **Critical / High**: pre-auth CMS chain proven E2E to takeover — Ghost
  `api_keys` secret -> signed Admin JWT read (CVE-2026-26980), Strapi admin
  `resetPasswordToken` extracted (CVE-2026-27886), Drupal anon SQLi extracting
  the uid=1 hash (CVE-2026-9082); authenticated/unauth SQLi that extracts
  password hashes / session or reset tokens / cross-tenant rows; NoSQL auth
  bypass into an admin account.
- **Medium**: boolean/time-blind confirmed and extracting non-sensitive data
  only (version, schema names) with no path to a secret yet; SQLi behind auth on
  a low-value, single-tenant object.
- **Low / skip**: a `SQLSTATE` in an error with no extraction proven (that is
  rung 0, not a finding — climb it); a time anomaly you cannot make repeatable.
- **Watch dups** — Ghost and the Next.js/CMS CVEs are mass-exploited the moment
  they drop; **be FIRST or expect dup**. The heavily-farmed CVEs (Ghost) tend to
  come back duplicate; the less-saturated ones (Strapi `where` oracle) are more
  likely to land as not-dup — check the corpus + disclosed reports before you
  invest.

Do NOT inflate a reachable/erroring param into a High. Either climb to the
extracted secret or grade it for the read you actually demonstrated.

## Non-destructive rules (every step)

- **Scope is a safety boundary, not a hunting filter.** The host you inject must be
  one the program authorized; payload *values* are never scoped — a UNION, a `$ne`,
  a hex literal, `EXP(710)`, a victim uid in a `WHERE`, a `$startsWith` prefix are
  all legal payload content. Your OOB listener is your own infrastructure and is a
  legal exfil destination. If a host is genuinely out of scope, pivot surface.
- **READ-ONLY. Never `DROP`/`DELETE`/`UPDATE`/`INSERT`.** No stacked write
  queries (`;DROP…`), no `xp_cmdshell`, no `COPY … TO/FROM PROGRAM`, no
  `LOAD_FILE`/`INTO OUTFILE` writes, no `sp_configure` on real infra.
- **Time-based: keep delays short (≤5s) and requests few.** Repeatable-but-brief
  beats hammering a 10s sleep 500 times — that is a self-inflicted DoS the program
  penalizes.
- **Extract the minimum.** One admin hash, one reset token, one schema row — the
  proof of the class. NEVER binary-search your way through an entire users table
  to "show scale"; state scale by inference (rung 3).
- **CMS reset-token chains: extract the token, do NOT spend it.** Proving you can
  read the admin's `resetPasswordToken` is the finding; actually resetting the
  admin's password is a rung-5 state change on another user — not attempted: ask d0x directly before executing.
- **Ghost Admin JWT: read-only.** Sign it, `GET` one admin object to prove
  takeover; never create/delete real content (a create-then-delete of a
  `__poc__` post you own is the max, and only if needed).
- **NoSQL auth bypass into a real user's account**: prove entry and stop — do not
  browse their data on prod (rung 3/5).
- **Nothing will stop you.** The rung is decided before the query is sent, by
  reading the ladder — no guard fires afterwards to tell you a line was crossed.
  When a step would be rung-3-on-prod / other-user-data / a write, drop to the
  safe-ladder equivalent (non-PII read on prod, or the full extraction on UAT)
  yourself; if neither reaches it, send the exact request and rollback plan to
  the primary agent so it can ask d0x directly. Continue independent safe angles.
- **Flag any extracted credential/hash/token for rotation** in the report.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- Pre-auth CMS SQLi CVEs (Drupal CVE-2026-9082, Ghost NQL CVE-2026-26980, Strapi
  CVE-2026-27886) are owned by `references/cms-cve-chains.md` **in this skill** —
  they are not `rce-hunting`'s, which has no boolean-oracle extraction methodology.
- A param you still need to find in the JS bundles -> `js-source-to-sink` (it hands
  back the endpoint + param here).
- An extracted hash / API secret / key to *exercise* (Ghost `api_keys`, a leaked
  service key, a crackable hash) -> `exposed-secrets` (check
  `../_shared/references/public-by-default-keys.md` first).
- SQLi that yields another tenant's rows / an id to swap -> `idor-bola` /
  `tenant-isolation`.
- Injection sink that reaches a URL fetch / file read for OOB -> `ssrf-safe` for the
  OOB listener path.
- About to claim Critical/High or ATO -> `validation` re-proves first
  (rejects a `SQLSTATE`-only "finding" with no extraction as thin).
- Confirmed bug -> `report-writing`.
