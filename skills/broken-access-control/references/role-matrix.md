# Role Matrix — function-level escalation to proven impact

<!-- workspace rung mapping -->

> **Rung mapping.** This file was written against a five-rung safety ladder. In this workspace those rungs are: **1** read-only · **2** write to an object _you_ own, reverted immediately · **3** bounded scale proof, 5–10 records, never a dump · **4** the same proof relocated to a UAT/OAT host · **5** anything touching a third party's object — **pause and ask d0x directly before executing**, providing the exact request, affected state and rollback plan. This is interactive routing, not a terminal state.

## Contents

- Method
- 1. Any valid token (incl. guest/anonymous) → admin route namespace (+ WAF-origin bypass — this file owns it)
- 1b. The 403-bypass ladder — PATH dimension, then METHOD dimension (this file owns both)
  - path transforms (incl. Next.js CVE-2025-29927)
  - method transforms: verb switching, override headers, the edge-rule combination
  - the framework override matrix (tested on this host)
  - oracle, controls, response-shape traps
  - rung: read verbs are rung 1, mutating verbs are rung 5
- 2. Dual-authorizer: Cognito JWT on an IAM-only admin gateway
- 3. UI-disabled vs server
- High-value privileged actions to matrix
- Demonstrate scale (bounded — 5–10 records, read-only)
- Good evidence
- False-positive gates

Use when the product has multiple roles/permission bits, an admin route group, or a second/internal API gateway. Vertical privilege: a low/no-privilege actor performs a privileged action server-side. Safe ladder: the **Rung mapping** above.

## Method

1. Create/identify operator accounts for each role, plus an **anonymous/guest** and an **API-token** actor. From `targets/<program>/accounts.md`.
2. Walk the privileged actor's UI and record every request a low actor should not perform (URL/method/body/op-name), plus every `*.execute-api`/internal gateway host in the JS.
3. **Negative control first**: fire each privileged request with no auth and with the low actor → record the denial. That denial is what turns the bypass into a finding.
4. Replay with the restricted/anon actor against synthetic objects.
5. Find the **sibling that enforces** (list vs detail, v2 vs v1, web vs internal gateway) — it proves the missing check.

## 1. Any valid token (incl. guest/anonymous) → admin route namespace

A high-yield function-level shape: any _valid_ token — including a credential-free guest — is accepted on the admin route family with no role enforcement, because the group checks authentication but never re-checks role.

- **Recognize** an admin/back-office route namespace (an `/api/admin/*`-style prefix, a `*-mgmt`/console/internal group) that the normal UI never calls, discovered in JS or source maps; plus any unauth path that mints a _usable_ bearer — a guest/anonymous/ "public" login, or a hardcoded key in the JS that exchanges for a token.
- **Attack**: mint the guest/anon token, then replay it across the admin-namespace routes (no role was ever proven).
- **Oracle ladder**: no token → 401; guest token on a normal route → 200 (token is valid); guest token on an admin-namespace route → 200 + data (role never checked); a sibling admin route that DOES enforce → 403 (proves a missing per-route check, not a globally open door). The admin group commonly spans 20+ sibling routes.

The guest-login / hardcoded key is a **public client input**, not a secret leak (the root `AGENTS.md`) — report the missing role check behind it, not the key.

**WAF-origin bypass** (universal — when the edge blocks the direct host). The origin IP leaks in the domain's SPF record more often than anywhere else; if SPF is clean, walk the rest of the ladder.

```bash
dig "$ROOT" TXT +short          # SPF: read the ip4:/include:/a:/mx: mechanisms -> origin candidates
dig +short "$ROOT" A ; dig +short "origin.$ROOT" A ; dig +short "direct.$ROOT" A
# then dial the origin directly, keeping the Host header intact:
curl --resolve "$HOST:443:<ORIGIN_IP>" "https://$HOST/<admin-route>" \
  -H "Authorization: Bearer $TOK"
```

Other origin-discovery vectors, in order of yield: historical DNS (a pre-WAF A record), a sibling subdomain resolving to the same origin, the cloud load-balancer DNS name, other TXT/DMARC records, and a bare Host-header override to the origin host.

Oracle: the edge returns 403/blocked on the path while the origin returns 200 with data for the identical request = the control is edge-only.

Converts: **Critical** when the admin group returns cross-user PII; **High** when it returns non-PII privileged data. The reachable route alone is not a finding.

## 1b. The 403-bypass ladder — PATH dimension, then METHOD dimension

One ladder, two dimensions of the same defect: the component that makes the authorization decision (edge rule, WAF signature, gateway spec, framework middleware) and the component that dispatches the request (origin route matcher, controller action) do not agree about **what the request is**. Disagree about the _path_ and a normalization transform slips past the check; disagree about the _method_ and a verb or an override header slips past it. Walk the path transforms first — they are read-only and cost nothing — then the method transforms.

**This section is the pack's single owner of both dimensions.** Any other skill that hits a 401/403 worth bypassing keeps a one-line recognition of the shape it owns and links here for the ladder itself — it is never copied. `../../auth-flow-bypass/references/acl-proxy-cache.md` owns the proxy/cache-ACL and source-IP differentials and defers every path and method transform to this file; card 7b of `../SKILL.md` is this skill's own recognition line.

**One dimension is NOT here: the front tier as a path FILTER rather than an authenticator.** When the edge/CDN/proxy/gateway enforces an allowlist over _paths, extensions or selectors_ and the origin re-parses the same bytes with a richer grammar (path parameters, selectors, format extensions, percent-decoding, dot-segment resolution), the ladder is `edge-filter-bypass.md` — it owns selector/extension smuggling, `;` path parameters, `..;/`, unanchored-regex suffixes, `nocanon` raw-path proxying, and the response **size differential** that tells you whether the edge or the origin answered. The transforms in this section are the authorization-decision subset; go there when the question is "which tier resolved this URL" rather than "did the gate fire".

### Path transforms

Replay the identical authenticated request, **one transform at a time**:

```
/admin/  →  /admin  →  //admin  →  /./admin  →  /admin/.  →  /admin;/  →  /admin%2f
        →  /%2e%2e/admin  →  /aDmIn  →  /admin.json  →  /admin.css  →  /admin?
        →  /admin#  →  /admin.  →  /admin%20  →  /admin/..;/
```

Plus four transforms the edge regexes miss most often: `/admin%09` (tab), `/%61dmin` and `/adm%69n` (percent-encode any single character — the origin decodes, the regex does not), the **absolute-form request line** (`GET http://127.0.0.1/admin HTTP/1.1`, which many proxies forward verbatim), and an **internal-vhost `Host:`** (`Host: localhost` / `Host: 127.0.0.1` on the blocked path, where the origin trusts the vhost).

Routing/override headers on the blocked path: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-Prefix`, `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`.

**Next.js CVE-2025-29927** — send `x-middleware-subrequest: middleware` (or the chained `middleware:middleware:middleware:middleware:middleware` form) on the gated path; if middleware auth is skipped, the route serves. Fingerprint the version from `/_next/static/` chunk banners first: affected from `1.11.4`, fixed in `12.3.5`, `13.5.9`, `14.2.25` and `15.2.3` (GHSA CVSS 3.1 9.1).

### Method transforms — same path, same credentials, different verb

Two distinct causes. Tell them apart, because they convert differently:

- **the route is not registered for that verb** — the framework falls through to a catch-all (`app.all`, `ANY`, a servlet default) or to a second controller that was never wired to the authz middleware. Often ends in a 405 instead of data;
- **the authorization rule is bound to the verb** — an edge/WAF rule written as "block `POST /admin`", a middleware registered as `app.post(...)`, an Apache `<Limit GET POST>` block, an API-gateway spec that lists only some methods. This is the one that pays, because the rule author was thinking about _writes_ while the data behind the route is readable.

Walk the verbs against the blocked path, in this order — read verbs first:

```
GET  →  HEAD  →  OPTIONS  →  POST  →  TRACE  →  PATCH  →  PUT  →  DELETE
```

Then, on a `POST` that the edge lets through, the override headers and parameters:

```
X-HTTP-Method-Override: <VERB>     highest yield - honoured by 4 of the 6 stacks below
?_method=<VERB>                    query string   - Laravel/Symfony-with-opt-in, Express
_method=<VERB>                     form-encoded or multipart body - Rack/Rails, Laravel
X-Method-Override: <VERB>          hand-rolled middleware spelling - no stack below took it
X-HTTP-Method: <VERB>              Microsoft / OData spelling - untested here, spray it
```

Proven on a two-process lab on this host (`python3` edge on `:8805` with a rule bound to the method, in front of an origin that honours the override header). Real output:

```
--- 1 CONTROL: DELETE straight at the edge
{"error":"edge: unsafe method blocked by WAF rule"} [403]
--- 3 SAFE PROBE: POST + override DELETE on a NONEXISTENT id
{"effective": "DELETE", "on_the_wire": "POST", "error": "no item 999999 - nothing deleted"} [404]
```

Line 3 is the whole technique in one request: on the wire it is a `POST`, so the method-bound edge rule never fires; the origin resolved it to `DELETE` and reached the delete handler; the `404` proves it got there **without touching a single object**.

### Framework override matrix — tested on this host, not recalled

Installed the real packages and drove them with `curl`. Every cell below is an observed response, and the surprising ones are the ones that matter.

| stack (version tested) | `X-HTTP-Method-Override` | `_method` in body | `_method` in query | rewrites which verb | precedence |
| --- | --- | --- | --- | --- | --- |
| Rack 3.2.6 `Rack::MethodOverride` (in Rails' default middleware stack) | yes | yes — form-encoded/multipart only | **no** | POST only | body param beats header |
| Symfony HttpFoundation 7.4.14, out of the box | **yes, no opt-in** | no | no | POST only | — |
| same + `enableHttpMethodParameterOverride()` (what Laravel's `Request::capture()` calls) | yes | yes — form-encoded | **yes** | POST only | header beats body |
| Express 5.2.1, no `method-override` mounted | no | no | no | — | — |
| `method-override` 3.0.0 as `methodOverride('X-HTTP-Method-Override')` | yes | no | no | POST (`opts.methods` default) | — |
| `method-override` 3.0.0 as `methodOverride('_method')` | no | **no** | **yes** | POST (`opts.methods` default) | — |

Four consequences worth carrying to a target:

- **Symfony honours the header with nothing enabled.** `getMethod()` in 7.4.14 reads `X-HTTP-METHOD-OVERRIDE` on any POST before it ever consults the parameter-override flag. `_method` is the opt-in half; the header is not. So on a PHP target, spray the header first — it works on plain Symfony, not just Laravel.
- **Symfony has no verb allow-list by default** (`$allowedHttpMethodOverride` is null): `X-HTTP-Method-Override: FOO` was accepted and `getMethod()` returned `FOO`. Rack does have one (`GET HEAD PUT POST DELETE OPTIONS PATCH LINK UNLINK`) and silently ignored `_method=FOO` — the request stayed a POST and hit the 403. A verb the app doesn't expect is a routing probe, not a failure.
- **Symfony 7.4 deprecates overriding to `GET`/`HEAD`/`CONNECT`/`TRACE`** and the shipped source says it "will be ignored in Symfony 8.0". On a Symfony 8 target the cheap read-verb override is dead and only the mutating verbs remain — i.e. the rung-5 shape. Check the framework version before concluding the app is not overridable.
- **`method-override`'s README is wrong about where a plain string looks.** It says a string getter reads `req.body[getter]`; the shipped `createGetter` routes anything not starting with `X-` to a **query-string** getter. Measured: `_method=GET` in the body → `403`, the same value in the query → `200 {"seen":"GET","orig":"POST"}`. On an Express target put `_method` in the **query** first.

Two configurations turn this from a bypass into a CSRF gadget, both observed: `methodOverride('_method', { methods: ['GET','POST'] })` rewrote a plain `GET /items/42?_method=DELETE` into `{"effective":"DELETE","on_the_wire":"GET"}`, which is reachable from `<img src>`; and **CVE-2026-42551** (flightphp/core `< 3.18.1`, fixed 3.18.1, CVSS 3.1 7.5) is that same defect shipped as a default — `Request::getMethod()` honoured the override header and `$_REQUEST['_method']` on _any_ verb with no opt-in, bypassing middleware gated only on POST/DELETE and poisoning CDN caches (the edge caches a GET response body for a request the origin executed as a DELETE).

**Untested on this host — recognize, then verify on the target.** No .NET runtime here, so ASP.NET/IIS handling of `X-HTTP-Method` and `X-HTTP-Method-Override` is a spelling to spray, not a verified row. `X-Method-Override` was fired at Rack and did nothing (403, no rewrite); Symfony's `getMethod()` and `method-override`'s getters read only the one exact header name, per the source shipped on disk — so that spelling only ever pays against hand-rolled middleware. Keep it in the spray and let the target answer.

### The combination that pays: a gateway rule bound to the method

The header only matters when something in front of the app makes its decision from the verb on the wire. That is not hypothetical — it is a shipped-product CVE:

- **CVE-2023-30845** — Google ESPv2 (the Cloud Endpoints / API Gateway proxy), `2.20.0` through `2.42.0`, fixed in `2.43.0`, NVD CVSS 3.1 **9.8**. NVD, verbatim: "ESPv2 2.20.0 through 2.42.0 contains an authentication bypass vulnerability. API clients can craft a malicious `X-HTTP-Method-Override` header value to bypass JWT authentication in specific cases." The vendor advisory pins the condition: when the real HTTP method is **absent** from the API specification and the override value is **present** in it, ESPv2 forwards to the backend without checking the JWT. Fingerprint ESPv2 on any `*.endpoints.*.cloud.goog` / Cloud Endpoints or API Gateway front end.
- **CVE-2017-12617** — Apache Tomcat `9.0.0.M1`–`9.0.0`, `8.5.0`–`8.5.22`, `8.0.0.RC1`–`8.0.46`, `7.0.0`–`7.0.81` with the Default servlet's `readonly` set to false: a `PUT` uploads a JSP which then executes on request. NVD CVSS 3.1 **8.1**. (`CVE-2017-12615` is the Windows-only `7.0.0`–`7.0.79` predecessor, same 8.1.) This is the pure "an unprotected verb reaches a handler" case — if `OPTIONS` advertises `PUT` on a Tomcat target, that is the one to check, and the result is RCE → `../../rce-hunting/SKILL.md`.

### Oracle

**The same path, the same credentials, the same body — only the method (or the override header) differs — returns a different authorization outcome.** Capture four things:

1. the **enforcing verb** → 403 (the negative control);
2. the **bypassing verb** → 200 **with the restricted body**;
3. the **enforcing sibling** — another route on the same host that denies on _every_ verb, proving the gap belongs to this route rather than the whole app. Real output from the lab: `GET /billing/plan` with no token → `{"error":"forbidden"}` `[403]` while `GET /admin/users` with no token returned the two-row user list;
4. for an override header, the **same request minus the header** → back to 403. Without this, you have not shown the header did it.

Lab output for 1–3, verbatim, against a handler whose edge rule inspects POST only:

```
### 1. POST (edge-inspected, no admin token) -> control
403
### 3. GET same path, same (no) creds -> the bypass
{"total": 2, "data": [{"id": 1, "email": "a@example.test"}, {"id": 2, "email": "b@example.test"}]}
-- 200
### 7. enforcing sibling /billing/ GET (no token)
{"error":"forbidden"}
-- 403
```

**Response-shape traps** — each of these looks like a bypass and is not:

- a 200 whose body is the login page or the SPA shell — same trap as the path ladder, compare bodies, not statuses;
- `HEAD` → 200 with `Content-Length: 0`: the framework auto-derived HEAD from the GET route and dropped the body. You proved routing, not disclosure. It only becomes evidence when the length matches the GET body or a header leaks the data — the lab returned `Content-Length: 98` and `X-Total-Count: 2` on a HEAD whose body was suppressed, and _that_ is a disclosure oracle you can quote;
- `OPTIONS` → 204 with a permissive `Allow`: usually a CORS preflight handler answering for every route, not the route's real verb set. Rung 0 — a lead about which verb to try next, never a finding;
- 405 from the _origin_ after the edge let the verb through: the route simply is not registered for it. Not a finding — but it does prove the edge rule is verb-bound, so keep walking the ladder with a verb the route accepts;
- `TRACE` reflecting your request: real (lab returned `message/http` echoing the `Cookie:` header) and worth **nothing** on its own. Browsers have not allowed TRACE from script for over a decade, so cross-site tracing has no delivery vector — `../../validation/references/auto-discard.md` rows 13 and 15 discard it. Keep it as a _dispatch_ oracle only: if TRACE reaches the origin, the edge is filtering by verb.

**curl mechanics that produce silent false negatives** — all three measured here:

- `curl -X HEAD <url>` fails **differently per server**, and always silently: measured `exit=124` (hung until `timeout` killed it) on WEBrick, `exit=18` (partial transfer) on `python3 -m http.server`, and a clean return on `php -S`. Because the failure mode is server-dependent, never use `-X HEAD` — use `-I` / `--head`, which returned `200 in 0.000462s` on every server tested.
- a body-less `POST` needs `-d ''` (or `-H 'Content-Length: 0'`). Without it the lab's WEBrick answered `411 Length Required` on _every_ probe — which reads exactly like "the bypass failed" while nothing was ever tested.
- `-d` also sets `Content-Type: application/x-www-form-urlencoded`, and that is load- bearing: Rack reads `_method` only from form-encoded or multipart bodies. The same `_method` inside a JSON body returned `403` on both Rack and Symfony.

### Rung — the part that can cause damage

**Switching to a READ verb is rung 1.** `GET`, `HEAD`, `OPTIONS`, `TRACE` against a blocked path change no state; fire them freely, including on prod.

**Switching to a MUTATING verb — `PUT`, `PATCH`, `DELETE`, or an override that resolves to one — against a real object is rung 5.** It deletes or overwrites data, and on a target you do not own it deletes _someone's_ data. ask d0x directly before executing (the **Rung mapping** above rung 5). There are two safe substitutes, and you should reach for one before you even consider asking:

- **a well-formed but nonexistent object id.** The handler answers `404` _after_ the verb has cleared the edge rule and the router — which is the entire claim. The lab proof above is exactly this: `POST /items/999999` + `X-HTTP-Method-Override: DELETE` returned `{"effective": "DELETE", "on_the_wire": "POST", "error": "no item 999999 - nothing deleted"}`. Nothing was touched, and the bypass is proven. **Caveat: not for `PUT`.** REST upsert semantics mean `PUT /items/<new-id>` may _create_ the object rather than 404. Probe with `DELETE` or `PATCH`; if the route only accepts `PUT`, use an object you created.
- **an object you created yourself**, then the follow-up canonical read as the persisted-state oracle. Lab: `POST /items/2` + override `DELETE` returned `{"deleted": "2", "remaining": ["1"]}`, and the follow-up `GET /items/2` returned `"item": "gone"` while `GET /items/1` still returned the record — the sibling is the control that shows you removed exactly one thing and nothing else.

Never spray the verb ladder across a route family with a wordlist. One path, one verb at a time, read verbs exhausted before any mutating verb is even loaded into the command.

### Converts?

- **Read verb reaching a restricted body** — grade by what the route returns, exactly as in §1: **Critical** for cross-user PII, **High** for non-PII privileged data, **Medium** for privileged metadata. The verb switch is rung 0; the body is the finding.
- **Override header reaching a read** — same grading, and it is a _stronger_ report than a bare verb switch because the negative control (same request, header removed → 403) is unambiguous. When the front end is a gateway, name the CVE-2023-30845 shape.
- **Override header reaching a WRITE** — **High**, **Critical** with a privileged effect (delete another actor's object, flip a role, cancel a payment). Proven on a nonexistent id it is still a real finding: say plainly that the verb cleared the control and the write path was reached, and state the effect by inference rather than performing it. A triager accepts that; a deleted production record ends the engagement.
- **`405` differential, `Allow` enumeration, `TRACE` reflection, a `HEAD` with an empty body** — **informative, all four.** They are routing evidence that tells you which verb to try next. Filed as a finding they close as `no-poc` (`../../validation/references/auto-discard.md` row 13). Put them in `notes/`, not in a report.
- **A method differential with no enforcing sibling** — deflate it. If _every_ route on the host answers every verb the same way, you have found an app with no method routing, not a broken authorization decision. Find the sibling that enforces, or drop it.

## 2. Dual-authorizer: Cognito JWT on an IAM-only admin gateway

JS exposes a second/internal gateway (`*.execute-api.<region>.amazonaws.com/<stage>`, often via a `getIntegrationApiEndpoint`-style helper). Most of its routes require IAM SigV4 — a plain JWT returns `"Credential should be scoped to a valid region"` — but a Cognito JWT authorizer was left on a few, and the Lambda does zero ownership validation.

- **Recognize**: probe the internal gateway's routes with a plain Cognito `id_token` — the IAM error on most, a 200 on a few. Among the 200s, find one that names a source object owned by another account AND a caller-controlled destination (a copy / clone / export / share action with a destination email/account field).
- **Attack**: resolve the victim's account id from an enumeration route (email→id lookups are common), then invoke the copy/clone route with the victim's object as source and your own identity as destination. The object (and its S3-backed content/ secrets) is cloned into your account; read it through the main API's normal presigned-URL route.
- **Oracle**: the internal route accepts your plain JWT (not the IAM error) AND acts on an account/object id you do not own; a sibling internal route still returns the IAM error → the authorizer was left on by mistake. Self-signup returning `UserConfirmed:true` lowers the bar to a throwaway attacker account.

This is a **function+object hybrid** — own it here, do not punt to idor-bola.

Converts: **High** when a JWT-accepting route lacks the ownership check AND a caller-controlled destination exposes another account's object; **Medium** if only the authorizer gap is proven.

## 3. UI-disabled vs server

A hidden/greyed button is nothing. Re-issue the exact request the enabled UI would send, with the restricted role's session, then confirm with a canonical read that state persisted. Only server response + persisted state count.

## High-value privileged actions to matrix

invite/remove members; change roles/permissions; owner transfer; billing/payment settings; API-token create/delete/rotate; export/download private data; update customer/company/org records; create leads/referrals/opportunities; admin-only settings; visibility/public-private toggles; 2FA policy settings.

## Demonstrate scale (bounded — 5–10 records, read-only)

After the class is proven on your own two accounts, show it is systemic without dumping the table (safe-ladder rung 3):

```bash
for i in $(seq 1 10); do
  curl -s -H "Authorization: Bearer $GUEST" \
    "https://$HOST/<paginated-admin-route>?page=$i" \
    | jq '{page:'"$i"', count:(.data|length), sample:(.data[0]|{id,email})}'
done
# or: ffuf -u "https://$HOST/<object-route>/FUZZ" -w <(seq 1000 1010) \
#          -H "Authorization: Bearer $TOKEN" -mc 200 -o scale.json -of json
```

Ten distinct records/emails = "systemic, N-user impact" by inference → Medium→High. Then STOP. Nothing enforces that ceiling but you: decide before the loop is written whether ten reads is rung-3-on-prod, and if it is, take one read + inference, or run it on UAT.

## Good evidence

- negative control (no-auth / low-role denial) + the successful bypass side by side;
- sibling endpoint denies while target endpoint allows;
- docs/UI/permission label says the actor should not have access;
- persisted server state (follow-up canonical read), not just a 200.

## False-positive gates

- UI hidden but the API is intentionally public;
- role inherits the permission through another group;
- action succeeds only on an actor-owned object with no privilege gain;
- 200 but no state change / no cross-actor data.
