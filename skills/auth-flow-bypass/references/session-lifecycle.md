# Session Lifecycle — fixation, invalidation, revocation

## Contents
- Ownership split
- Invariants (each is a finding when missing)
- Local harness — prove the capture/replay mechanics before touching the target
- A — Fixation: no rotation on login
- B — No rotation on privilege elevation (role change, step-up MFA, sudo mode)
- C — No invalidation on logout
- D — No invalidation on password change / reset / email change
- E — Refresh token / OAuth grant survives revoke
- F — Concurrent-session inventory gap
- G — Remember-me / long-lived persistent token
- H — JWT specifics: a stateless token has nothing to revoke
- Good evidence
- False-positive gates (rotate, don't report)
- Ladder discipline

Use when the target has a login. The finding is **a credential that is still
accepted after the event that was supposed to end it** — or a credential the
attacker chose *before* the victim authenticated. A `Set-Cookie: SID=; Max-Age=0`
on logout is rung 0; the proof is the old value returning authenticated data.

Every proof in this file is **safe-ladder rung 2, operator's own account only**
(`../../_shared/references/safe-ladder.md`). No second user, no victim, no write
to anything but the operator's own session state — which makes this the safest
high-value class in the pack. Run it on every target with a session.

## Ownership split

- **This file owns SESSION lifecycle**: the credential's birth (rotation) and
  death (logout, password/email change, revoke, device list, persistence).
- Access that outlives **ROLE / SEAT / GRANT removal** — a removed org member's
  PAT, a downgraded plan's token, a banned user's API key — is owned by
  `../../broken-access-control/references/lifecycle-persistence.md`. Rule of
  thumb: the *identity* stays and the *session* should have died -> here; the
  *entitlement* was removed and access remains -> there.
- Forging or tampering with the token -> `jwt-attacks.md`. This file only asks
  whether a **valid, unmodified** credential is still honoured.
- The remembered-device cookie as a **second-factor** bypass -> `mfa-session.md`
  E. The persistent **authentication** cookie surviving invalidation is §G here.
- OAuth code/token exchange mechanics -> `oauth-code-token.md`; refresh-token
  *survival of a revoke event* is §E here.

## Invariants (each is a finding when missing)

- login issues a **new** session identifier and the pre-auth one dies;
- so does every privilege elevation (role change, step-up MFA, sudo/re-auth);
- logout deletes the session **server-side**, not just the browser cookie;
- password change / reset / email change kills **every other** session and every
  refresh token;
- revoking a token or app in the account UI kills the **grant**, not only the
  current access token;
- every live credential appears in the active-devices list and is killable there;
- persistent "remember me" tokens die with all of the above.

## Local harness — prove the capture/replay mechanics before touching the target

Session testing fails silently when the *mechanics* are wrong (a cookie jar that
quietly re-sends a rotated value, an `awk` field that picks the wrong column) and
the operator reads the result as "the app is fine". Calibrate against a local app
whose behaviour is known, then point the identical commands at the target.

```bash
cat >/tmp/sessd.py <<'PY'
"""sessd.py - local session-lifecycle harness (stdlib only).
MODE=vuln : sid survives login, logout, password change (the bug)
MODE=safe : rotates on login, kills on logout / password change (the control)"""
import json, os, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("MODE", "vuln")
S = {}                                    # sid -> user  (None = pre-auth session)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def sid(self):
        c = self.headers.get("Cookie", "")
        return dict(p.strip().split("=", 1) for p in c.split(";") if "=" in p).get("SID")

    def out(self, code, obj, ck=()):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        for c in ck:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        s = self.sid()
        if self.path == "/":                                  # pre-auth session issued
            if s in S:
                return self.out(200, {"sid": s})
            n = secrets.token_hex(8)
            S[n] = None
            return self.out(200, {"sid": n}, [f"SID={n}; Path=/; HttpOnly"])
        if self.path == "/me":                                # the protected route
            if S.get(s):
                return self.out(200, {"user": S[s], "sid": s})
            return self.out(401, {"error": "unauthenticated"})
        self.out(404, {})

    def do_POST(self):
        s = self.sid()
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/login":
            if MODE == "vuln" and s in S:
                S[s] = "alice"                                # no rotation = fixation
                return self.out(200, {"sid": s})
            S.pop(s, None)
            n = secrets.token_hex(8)
            S[n] = "alice"
            return self.out(200, {"sid": n}, [f"SID={n}; Path=/; HttpOnly"])
        if self.path == "/logout":
            if MODE == "safe":
                S.pop(s, None)                                # server-side kill
            return self.out(200, {"ok": True}, ["SID=; Path=/; Max-Age=0"])
        if self.path == "/password":
            if MODE == "safe":
                u = S.get(s)
                for k in [k for k, v in S.items() if v == u and k != s]:
                    S.pop(k)
            return self.out(200, {"changed": True})
        self.out(404, {})


ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "8131"))), H).serve_forever()
PY
MODE=vuln PORT=8131 python3 /tmp/sessd.py & MODE=safe PORT=8132 python3 /tmp/sessd.py &
sleep 1
```

The capture/replay procedure, run against both ports — `8131` is the bug, `8132`
is the negative control. These are the same commands used against a real host,
with `$H` swapped for `https://app.target.com`:

```bash
H=http://127.0.0.1:8131; J=/tmp/s.jar; rm -f $J
curl -s -c $J $H/ -o /dev/null                                  # 1. pre-auth session
PRE=$(awk '$6=="SID"{print $7}' $J)                             #    jar: $6=name $7=value
curl -s -b $J -c $J -X POST $H/login -d 'user=alice&pass=x' -o /dev/null   # 2. authenticate
POST=$(awk '$6=="SID"{print $7}' $J)
[ "$PRE" = "$POST" ] && echo "FIXATION: sid not rotated on login" || echo "rotated (correct)"
curl -s -w ' [%{http_code}]\n' -H "Cookie: SID=$PRE" $H/me      # 3. replay the OLD value
```

Observed — `8131`: `pre` and `post` identical, `FIXATION: sid not rotated on
login`, and the replayed pre-auth value returns
`{"user": "alice", ...} [200]`. `8132`: the two values differ, `rotated
(correct)`, replay returns `{"error": "unauthenticated"} [401]`. That 200-vs-401
pair is the entire oracle for §A–§D; if the local run does not reproduce it, the
mechanics are broken and any target result is noise.

Two mechanics notes the harness confirms: curl writes HttpOnly cookies with a
`#HttpOnly_` prefix on the **domain** field, so `$6`/`$7` still hold; and
replaying with an explicit `-H "Cookie: ..."` (no `-b`) is what guarantees the
*old* value is sent rather than whatever the jar has since rotated to. The
harness models missing rotation only — it rejects an identifier it never issued
(`-H "Cookie: SID=attackerchosen"` then login -> `401`), which is the negative
control for the planting half of §A.

## A — Fixation: no rotation on login

The session identifier issued **before** authentication is still valid after it,
now carrying the authenticated identity. An attacker who can plant a known value
in the victim's browser is logged in as the victim the moment the victim
authenticates.

Procedure: the three steps above, on the target. Two fast pre-checks:

```bash
curl -s -c /tmp/j -D- https://$HOST/login -o /dev/null | rg -i '^set-cookie'   # pre-auth value
curl -s -b /tmp/j -c /tmp/j -D- -X POST https://$HOST/api/login \
  -d 'user=OPERATOR&pass=...' -o /dev/null | rg -i '^set-cookie'
```

**Oracle**: no `Set-Cookie` on the login response at all -> the server never
rotated; or a `Set-Cookie` whose value equals the pre-auth one. Then the decisive
step: the pre-auth value replayed standalone returns the authenticated `/api/me`.

Also test the **planting** half, because it is what makes this reportable: does
the app accept a session identifier the attacker supplies — `?sessionid=`,
`;jsessionid=`, a `Set-Cookie` from a sibling subdomain (host-only vs
domain-scoped), an unauthenticated endpoint that echoes an attacker-chosen
cookie? Set an arbitrary value first (`-H "Cookie: SID=attackerchosen"`), then
authenticate over it: if `/api/me` answers for `SID=attackerchosen`, the
identifier is fully attacker-selectable.

**Negative control**: login answers with a new `Set-Cookie` value and the pre-auth
value 401s.

**Converts?** **Medium** with a stated planting vector, **Low/informative**
without one — programs close bare fixation as "you fixed your own session". The
framing that gets it paid is naming the delivery: an accepted `?sessionid=`
parameter, a cookie-writing sibling subdomain (an XSS or takeover on
`*.target.com` writing a `Domain=.target.com` cookie), or a session identifier
the app itself accepts from the query string. With attacker-selectable values
plus no rotation it is a pre-auth ATO — **High**.

## B — No rotation on privilege elevation (role change, step-up MFA, sudo mode)

Same defect, later in the flow: the identifier survives a step-up. Elevate on the
operator's own account and diff the identifier across the boundary:

- password -> **step-up MFA / sudo mode / re-auth prompt**;
- user -> **admin/owner** role change inside an operator-owned org;
- free -> paid plan, or accepting an invitation that grants a new role.

```bash
B=$(awk '$6=="SID"{print $7}' /tmp/j)     # before elevation
# perform the elevation in the browser / via API
A=$(awk '$6=="SID"{print $7}' /tmp/j)     # after
[ "$A" = "$B" ] && echo "NOT ROTATED on elevation"
```

**Oracle**: identifier unchanged across the boundary. The impact is that a
session captured while the account was *unprivileged* silently inherits the
elevation — and, when the boundary is step-up MFA, that a pre-MFA session
identifier becomes a post-MFA one.

**Negative control**: a new identifier (or a distinct elevated token) after the
step-up.

**Converts?** **Medium** standalone. **High** when the boundary is step-up MFA or
sudo mode, because it turns into an MFA bypass — carry it to `mfa-session.md` F
and report the MFA impact, not the rotation.

## C — No invalidation on logout

```bash
A=$(awk '$6=="SID"{print $7}' /tmp/j)                      # capture, authenticated
curl -s -o /dev/null -w 'baseline %{http_code}\n' -H "Cookie: SID=$A" https://$HOST/api/me
# log out in the browser (or POST the logout endpoint) — then, from a clean context:
date -u; curl -s -w ' [%{http_code}]\n' -H "Cookie: SID=$A" https://$HOST/api/me
```

**Oracle**: 200 with the operator's identity after the logout timestamp. Note
*which* logout was used — many apps kill the session on the API logout but not on
the "sign out" link, or vice versa; and check the API/mobile/websocket surface
too, since a web logout frequently leaves the mobile token alive.

**Negative control**: 401 immediately after logout on every surface.

**Converts?** **Low to Medium** — this is the family member most often closed as
informative ("the cookie is cleared client-side"). It converts when the report
carries a *duration* and a *carrier*: the token still authenticating hours later
with a timestamped pair of requests, on a shared/kiosk device or after the token
leaked to a log/proxy/browser history. Do not file it alone if §D is also true —
§D subsumes it and rates higher.

## D — No invalidation on password change / reset / email change

The highest-converting member of this family. Changing the password is the
victim's own remediation after a compromise; if it does not kill the other
sessions, **the remediation does not work** and the attacker keeps the account.
Say exactly that in the report — it is the framing that moves this from
informative to paid.

Two sessions, both the operator's own account (two jars, or one browser + one
curl):

```bash
# A = the "already compromised" session, captured and set aside
A=$(awk '$6=="SID"{print $7}' /tmp/a.jar)
# B = the remediating device: change the password there
curl -s -b /tmp/b.jar -X POST https://$HOST/api/account/password \
  -d 'current=OLD&new=NEW' -o /dev/null -w '%{http_code}\n'
date -u; curl -s -w ' [%{http_code}]\n' -H "Cookie: SID=$A" https://$HOST/api/me
```

Run the same three-step shape for every event that is supposed to be
session-killing: password **reset** via the emailed link (a different code path
from an in-app change — test both), **email address change**, **MFA
enable/disable**, and an explicit "**sign out of all devices**" button. That
button failing is the strongest variant: the app made an explicit promise.

**Oracle**: session A returns 200 with account data after the change timestamp,
while the app's own security page claims the sessions were terminated.

**Negative control**: A 401s the moment the change lands, on every surface.

**Converts?** **Medium** baseline, **High** when any of these holds: the app
markets "sign out everywhere" / lists devices as revocable and the promise is
false; the reset flow (post-compromise remediation) is the one that fails; or the
surviving credential is long-lived (§G) so the attacker's persistence is
effectively permanent. Chain it with §E and §F in one report — "the victim cannot
see the session, cannot revoke it, and changing the password does not kill it" is
a single coherent High, whereas the three filed separately read as three
informatives.

## E — Refresh token / OAuth grant survives revoke

The access token dies on schedule and everyone declares victory; the refresh
token keeps minting new ones.

```bash
# 1. mint a pair on the operator's own account
T=$(curl -s -X POST https://$HOST/oauth/token -d 'grant_type=password&username=OP&password=...')
AT=$(jq -r .access_token <<<"$T"); RT=$(jq -r .refresh_token <<<"$T")
# 2. trigger the kill event: logout, password change, or "revoke app" in the account UI
# 3. the refresh still mints?
curl -s -X POST https://$HOST/oauth/token \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CID" | jq -c '{minted:has("access_token")}'
# 4. and the freshly minted access token actually works
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $NEW" https://$HOST/api/me
```

Target-shaped illustration (the local harness does not implement `/oauth/token`,
so this split is what a vulnerable-vs-correct pair looks like, not a recorded
run): the vulnerable side answers `{"minted":true}`, the correct side
`{"minted":false}`. On a target, step 4 is mandatory — a mint that returns a token
the API then rejects is not the bug.

Variants worth the extra request: revoking the app in the account UI leaves the
grant usable; `POST /oauth/revoke` returns 200 but only invalidates the token
passed to it; a refresh issued to a **first-party** client survives while the
third-party one dies; the refresh token is not rotated on use, so an old refresh
token stays valid alongside the new one.

**Oracle**: a `refresh_token` captured before the revoke mints an access token
after it, and that token returns account data.

**Negative control**: the refresh exchange 401s / `invalid_grant` after the event.

**Converts?** **High** when the refresh survives a **password change or reset** —
that is unkillable persistence after remediation. **Medium** when it only
survives logout or an in-UI "revoke app" that the user was told worked. Bare
"access token still valid until exp" is **not** a finding — that is what `exp`
means; see §H.

## F — Concurrent-session inventory gap

The account's "active devices / sessions" list omits credentials, so the victim
cannot revoke what they cannot see. Enumerate the credentials the operator
actually holds, then count the rows the app shows:

```bash
# hold, on one account: a web session, a mobile/API token, a remember-me cookie,
# a websocket, a PAT — then:
curl -s -b /tmp/j https://$HOST/api/account/sessions \
  | jq -c '{listed:(.sessions|length), kinds:([.sessions[].kind]|unique)}'
```

Target-shaped illustration (the local harness has no `/api/account/sessions`
route, so this is the shape to expect, not a recorded run): holding three
credentials, a vulnerable build reports `{"listed":1,"kinds":["web"]}` while a
correct one reports `{"listed":3,...}`. The gap between what you hold and what the
UI lists is the finding — those are the sessions the victim cannot revoke.

Also test the revoke button itself: kill a listed row and replay that exact
credential — a device list that displays a session but does not actually
terminate it is the same bug with a worse story for the vendor.

**Oracle**: credentials held > rows listed; or a row revoked from the UI whose
credential still returns 200.

**Negative control**: every credential minted appears, and revoking a row makes
that exact credential 401.

**Converts?** **Low / informative on its own** — file it as an amplifier inside
the §D or §E report, never standalone. It converts to **Medium** when the hidden
credential is *also* one that survives password change: at that point the victim
has no path at all to eject the attacker, which is the sentence that carries the
severity.

## G — Remember-me / long-lived persistent token

The persistent cookie (`RID`, `remember_token`, `persistent_login`,
`auth_token`, a mobile refresh cookie) is a second, longer-lived credential that
often bypasses every invalidation path above because it is stored in a different
table.

1. Log in with "remember me" ticked; capture **both** cookies from the jar.
2. Run §C and §D — but replay the **persistent** value, not the session one.
3. Read its lifetime: `awk '$6=="RID"{print $5}' /tmp/j` is the expiry epoch
   (`date -d @<epoch>`); a `Max-Age` of `31536000` is a one-year credential.
4. Check whether it is forgeable/portable rather than random — a value that
   decodes to `<userid>:<hash>` or survives being moved to another browser is a
   direct escalation (`deserialization-hunting` owns framework remember-me
   forging, e.g. Shiro).

**Oracle**: the persistent cookie alone (no session cookie) returns 200 on
`/api/me` after logout **and** after a password change.

**Negative control**: the persistent token is deleted alongside the session on
both events.

**Converts?** **Medium** standalone (a year-long credential surviving logout),
**High** when it survives a password change — it is usually the concrete carrier
that makes §D a High rather than a Medium, so lead the report with the persistent
token and its documented lifetime.

## H — JWT specifics: a stateless token has nothing to revoke

A signed JWT is valid until `exp` unless the server keeps a deny-list. The
question is not "can it be revoked" (by construction, no) but **whether any
server-side check exists at all, and how wide the window is**.

```bash
cut -d. -f2 <<<"$JWT" | python3 -c '
import sys,base64,json,time
s=sys.stdin.read().strip(); d=json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))
print({k:d.get(k) for k in ("sub","iat","exp","jti","sid")})
print("ttl_hours", round((d.get("exp",0)-time.time())/3600,1))'
```

Observed shape: `{'sub': 'alice', 'iat': ..., 'exp': ..., 'jti': 'a1b2', 'sid':
'sess-77'}` / `ttl_hours 720.0` — a 30-day access token.

**Oracle:** the *same, unmodified* JWT still returns 200 on a protected route
after a timestamped logout or password change. That is a missing `jti`/`sid`
deny-list, and the measured `ttl_hours` is the exact width of the window it leaves
open. Nothing is forged here — the token is the one the server issued you.

Then read both halves:

- **is there a deny-list?** Log out (or change the password), replay the *same*
  JWT. Still 200 -> no `jti`/`sid` check; the token is live for its whole `exp`.
- **how wide is the window?** `ttl_hours` above. Minutes is a design; 720 hours
  with no deny-list is a month of post-remediation access.
- a `jti` or `sid` claim present but unchecked is the strongest evidence: the
  design anticipated revocation and the check was never wired.

Forging, `alg` confusion, `kid`/`jku` injection and claim swapping are **not**
here — `jwt-attacks.md` owns them. This section only measures a valid token's
lifetime and revocability.

**Negative control**: the same JWT 401s after logout/password change (a deny-list
exists), or `exp` is short enough (minutes) that the window is not the finding.

**Converts?** **Do not file "JWT cannot be revoked" alone** — it is closed as
informative every time, because that is how stateless tokens work and the program
knows it. It converts only as the *mechanism* inside a §D report: "the password
change does not invalidate the session because the access token is a stateless
JWT with a 30-day `exp` and an unchecked `jti`" — that is a **Medium/High**
depending on the window and on whether the refresh token (§E) also survives.

## Good evidence

- pre-auth identifier and post-auth identifier are byte-identical, and the
  pre-auth value returns authenticated data on a protected route;
- an attacker-chosen identifier is accepted and carries the identity after login;
- a captured session returns 200 after a timestamped logout / password change /
  reset / "sign out everywhere", with the app's security page claiming otherwise;
- a refresh token captured pre-revoke mints an access token post-revoke, and that
  token returns account data;
- credentials held > rows in the active-devices list, or a revoked row whose
  credential still works;
- a persistent cookie with a documented multi-month expiry surviving both;
- the negative control alongside it: a sibling event (or the same event on
  another surface) DOES invalidate — proof the app knows how and simply missed
  this path.

## False-positive gates (rotate, don't report)

- the identifier changes but the app also keeps a second, unrelated tracking
  cookie stable — a stable analytics/CSRF/device cookie is not a session;
- the replayed value returns 200 on a **public** route only; `/api/me` 401s;
- logout kills the session and the browser simply still shows cached UI;
- the "still valid" token is a short-`exp` access token replayed inside its
  documented window — that is `exp` working, not a missing invalidation;
- the program documents multi-session behaviour and offers explicit per-device
  revocation that actually works;
- fixation with no planting vector and a server-generated random identifier —
  state it in `notes/` and rotate rather than filing an informative.

## Ladder discipline

Rung 2 throughout, and only the operator's own account. Concretely: never capture
or replay a session belonging to anyone else — a real user's cookie is rung 5 and
is not needed here, because every item above is fully proven with one operator
account and two of the operator's own browsers/jars. Changing the operator's own
test-account password to test §D is an own-account state change (fine); restore
the original password afterwards and note it. Do not trigger password resets
against any address the operator does not control. Flag every session, refresh
token, and persistent cookie exercised for rotation in the lead file under
`targets/<program>/leads/` (`../../_shared/references/output-contract.md`).
