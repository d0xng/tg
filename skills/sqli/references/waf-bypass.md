# WAF bypass — match the bypass to the parser, don't spray

Your oracle works locally but the payload gets `403`/`406`/blocked, or the
keyword is stripped. A WAF/normalizer sits between you and the DB. The fix is to
make the payload survive the WAF's tokenizer while still parsing as SQL to the
DB. Spraying every bypass is noise (and rate-limit bait) — identify what's being
blocked, then apply the matching transform.

## Diagnose first (one request each)

- Is it the **keyword** or the **quote**? Send `SELECT` alone, then `'` alone —
  whichever 403s tells you what to transform.
- Is it **case-insensitive**? `select` vs `SeLeCt`.
- Does it block on the **word** or the **regex `\bunion\b\s+\bselect\b`**? A
  comment/whitespace between them often defeats a naive regex.
- Is the block on the **URL** or the **body**? Move the param to a POST body, or
  vice-versa.

## The bypass ladder (apply the one that matches the block)

**Comments (split keywords / kill whitespace):**
- Inline: `UNION SELECT` -> `UNI/**/ON SEL/**/ECT` or `UNION/**/SELECT`.
- MySQL versioned (executes only in MySQL, invisible to some WAFs):
  `/*!50000UNION*/ /*!50000SELECT*/`, `/*!UNION*/`.
- Terminate & re-open: `SEL/**/ECT`.

**Case & keyword mangling:**
- `SeLeCt`, `UnIoN`, `oR`, `AnD` — beats case-sensitive signatures.
- Keyword equivalents: `AND`/`OR` -> `&&`/`||` (MySQL); `=` -> `LIKE` /
  `BETWEEN 1 AND 1` / `IN(1)`; `OR 1=1` -> `OR 1 LIKE 1` / `OR 2>1`.

**Whitespace alternatives (when spaces are blocked):**
- `%09` (tab), `%0a` (LF), `%0c`, `%0d`, `%a0`, `/**/`, `%2b` (+ in some ctx).
- Parenthesis to remove spaces entirely: `UNION(SELECT(1),(2))`,
  `SELECT(pass)FROM(users)WHERE(id)=(1)`.

**Encoding layers:**
- Single URL-encode the quote: `%27`. Double-encode when the WAF decodes once but
  the app decodes twice: `%2527` -> app sees `%27` -> `'`.
- Unicode/overlong or full-width where the app normalizes: `＇`, `Ｕ` variants.
- Hex/char literals to avoid quoted strings entirely: `0x61646D696E` (=`admin`,
  MySQL/Postgres), `CHAR(97,100,109,105,110)`, Postgres `CHR(97)||CHR(100)`.
- Concatenation to break a signature: `'ad'||'min'` (Postgres/Oracle),
  `CONCAT('ad','min')` (MySQL), `'ad'+'min'` (MSSQL).

**Value/number tricks (no quotes, no keywords):**
- Arithmetic boolean: `id=5-0` vs `id=5-1` (survives quote + keyword filters).
- Scientific notation as an error oracle that dodges `EXP`-word filters:
  `1e308*10` overflow; the Ghost chain uses `EXP(710)` — if `EXP` is filtered try
  `POW(9,999)` / `1e308+1e308`.
- `LIKE` instead of `=`; `RLIKE`/`REGEXP` (MySQL) as boolean oracles.

**Context switch (the strongest — change the parser you're fighting):**
- **JSON / array-key context** — the whole Drupal CVE-2026-9082 class: the WAF
  inspects string *values*, but the injection is in a JSON *key* it never
  normalizes. When body values are filtered, look for a key/operator sink.
- **Operator injection** (NoSQL) — `password[$ne]=x` carries no SQL keywords at
  all; a SQL-focused WAF sails right past it (`nosql-injection.md`).
- **HTTP parameter pollution**: `?id=1&id=2` — some stacks read the last, the WAF
  the first (or vice-versa); split a blocked payload across duplicates.
- **Verb / content-type**: move the param from URL to a JSON/`multipart` body, or
  switch `GET`->`POST`; many WAF rules only inspect one.

## Confirm each transform still parses as SQL

A bypass that defeats the WAF but breaks the SQL is useless. After each transform
re-run the **balanced-vs-unbalanced** or **1=1 vs 1=2** check
(`detection-fingerprint.md`) to confirm the oracle still fires. Then keep the
minimal transform — don't stack ten of them (that's more signature surface, not
less).

## Keep it non-destructive & quiet

- WAF tuning means a *few* crafted requests, not a fuzzing storm — mass payload
  spraying trips rate limits and the "no automated scanning" clause. If you must
  grind (char-by-char), hand the working bypass to `sqlmap` with
  `--tamper=<script>` + low threads/`--delay` (`blind-extraction.md`), still
  `--technique=BT`, never a write.
- Never let a bypass talk you into a stacked write — the transforms above are for
  READ oracles only.
