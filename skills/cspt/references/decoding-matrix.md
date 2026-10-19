# CSPT framework decoding matrix — which component decodes, and how

## Contents

- The matrix (per-framework: path param / query / splat / double-encode / tier)
- Reading the rows (React Router `%252F`, SvelteKit `%25`-split, Ember, Solid, hybrid server rows)
- Safe-pattern signals (the dev avoided the trap — deprioritize)
- Adjacent route-guard bypass — check on every Next.js target (CVE-2025-29927)
- Lab / reference repos (confirm decode behavior before reporting)

CSPT only exists when the router **decodes** the encoded traversal before the
value is interpolated into a `fetch()`. This file is the per-framework cheat
sheet for *which* component decodes and *which* encodings survive. Methodology
adapted from CTBB Show / xssdoctor's framework-decoding research
(`github.com/xssdoctor/cspt_research`) and Doyensec's CSPT2CSRF work
(`github.com/doyensec/CSPTPlayground`).

**PIN THE VERSION FIRST.** Every row below is current for late-2025 / early-2026
releases; frameworks patch decode behavior. Read the actual version from the
bundle (webpack/Vite chunk comments, a `package.json` fragment in a source map,
or the vendor chunk banner) and, if a row looks off, skim that version's router
source or reproduce it in the lab repo before trusting the matrix.

## The matrix

| Framework | Path param decode | Query decode | Splat / catch-all | Double-encode (`%252F`) | Tier |
|-----------|-------------------|--------------|-------------------|-------------------------|------|
| **React Router** (v6/v7) | per-segment `decodeURIComponent`, then a **case-sensitive** `.replace(/%2F/g,"/")` on the param | full | `path="x/*"` = `(.*)`, literal `../` matches across `/` | **`%252F` works, `%252f` does not** — Issue #10814; `%252F` decodes to `%2F`, which the case-sensitive replace collapses | high |
| **Vue Router** (v4) | full `decodeURIComponent` | full | `/:pathMatch(.*)*` decoded | no | high |
| **Angular** (`@angular/router`) | full `decodeURIComponent` on `paramMap.get` | full | wildcard `**` decoded | no | high |
| **Next.js (page / `useRouter` client)** | re-encoded → safe | full | re-encoded | no | medium |
| **Next.js (route handler `app/api/.../route.ts`)** | **full auto-decode** of `await params` | full | `[...path]` fully decoded | no | **critical** (server-side, SSRF-capable) |
| **Nuxt (client)** | full | full | full | no | high |
| **Nuxt (server `defineEventHandler`)** | safe by default; **`getRouterParam(e, 'p', { decode: true })` opts into decode** | n/a | safe by default | no | **critical** if the opt-in is used |
| **SvelteKit** | two-stage decode: `%2F` → `/` | full | `[...path]` decoded | **blocked** — normalizer splits on `%25`, `%252F` stays literal | high |
| **Ember** (`@ember/routing`) | dynamic segments decoded; wildcard `*param` stays **encoded** | full | wildcard safer (encoded) | blocked (idempotent normalize) | medium-high |
| **Solid / SolidStart** (`@solidjs/router`) | **never decoded** in the router | `useSearchParams()` decodes | catch-all keeps real `/` | n/a | low (router); shifts to query params / server functions |

## Reading the rows

- **React Router** is the classic. `matchRoutes` runs `decodePath()` —
  `decodeURIComponent` per path segment — and then `matchPathImpl` runs
  `(value||"").replace(/%2F/g,"/")` on the matched param. That replace is
  **case-sensitive**. The traversal therefore exists in `params` **before** any
  fetch is built; **nothing decodes `%2F` at fetch time**
  (`new URL('..%2fadmin','http://x/api/v1/').pathname` is `/api/v1/..%2fadmin`,
  and `fetch`/curl put `%2f` on the wire verbatim — only a literal `../`
  resolves). Payloads: `..%2f` and `..%2F` (single encode, collapsed by the
  per-segment `decodeURIComponent`) and `..%252F` (double encode → `..%2F` →
  replace collapses it). **`..%252f` lowercase does not work** — the replace only
  matches uppercase `%2F`, so the param stays `..%2f` and never becomes a
  traversal downstream. That is Issue #10814: `%252F` is the bypass when a naive
  filter strips single-encoded `../`. Measured on react-router 6.30.4 and 7.18.1.
- **SvelteKit** does a two-stage decode but its path normalizer splits on `%25`,
  so `%252F` (double-encoded) does **not** collapse — single-encode (`..%2f`) is
  the working payload; don't waste time on `%252f` here.
- **Ember** decodes dynamic segments (`:id`) but leaves wildcard `*param`
  encoded, so aim CSPT at dynamic segments, not the wildcard.
- **Solid's router never decodes** — a Solid CSPT lives in `useSearchParams()`
  (query decodes) or in server functions, not the path param. Don't burn cycles
  on Solid path params.
- **Hybrid server rows (Next route handler, Nuxt `{decode:true}`, SvelteKit
  `+server.ts`) are the Critical rows** — the server receives the decoded value
  and builds an *internal* fetch. That is secondary-context SSRF (`chains.md` §4),
  the CSPT outcome that most reliably reaches Critical. Always check the server side on these
  frameworks even when the client side looks safe.

## Safe-pattern signals (the dev avoided the trap — deprioritize)

Seeing any of these on the specific route means that route is likely safe; move
to a route that doesn't use them:

- React: `useLocation().pathname` (the raw, un-decoded path) instead of
  `useParams()`.
- Vue: `route.path` / `route.fullPath` (raw) instead of `route.params.x`.
- Angular: `router.url` (raw) instead of `paramMap.get(...)`.
- SvelteKit: typed route matchers `[id=id]` / `[slug=slug]` that reject `/`.
- **Any `encodeURIComponent(param)` wrapping the value before the fetch
  interpolation** — this re-encodes the traversal and defeats CSPT. Grep for it
  around every candidate sink; its presence is the single most common false
  positive killer.
- The fetch URL built with `new URL("../../admin", base)` — resolves at
  construction time, not fetch time. Verify the *actual* outbound string in the
  Network tab (see `chains.md` false positives).

## Adjacent route-guard bypass — check on every Next.js target

CSPT bypasses a *frontend* route guard because the guard inspects the route param
string, not the resolved fetch URL. On **Next.js** specifically there is a second,
unrelated route-guard bypass worth testing back-to-back because both defeat the
"the guard protected it" assumption:

- **CVE-2025-29927** — Next.js middleware (`middleware.ts`) authorization bypass.
  A request carrying the header `x-middleware-subrequest` with the middleware's
  module path (e.g. `x-middleware-subrequest: middleware` or
  `x-middleware-subrequest: src/middleware` — chain repeated segments up to the
  internal recursion limit, e.g.
  `middleware:middleware:middleware:middleware:middleware`) causes Next to treat
  the request as an internal subrequest and **skip the middleware entirely**,
  bypassing auth/redirect guards implemented there. Affects Next.js < 14.2.25 /
  < 15.2.3 (and the 11–13 lines via the equivalent header). Non-destructive to
  test: add the header to a request for a guarded page and observe whether the
  auth redirect is skipped and the protected content returns. If the frontend
  route guard is the *only* thing you can bypass with CSPT, this CVE may bypass
  the *server* guard on the same target — grade and report separately.

This is not CSPT, but it belongs in the same session on a Next.js target: both
are "the guard checked the wrong thing." Confirm the Next.js version first.

## Lab / reference repos (confirm decode behavior before reporting)

- `github.com/xssdoctor/cspt_research` — per-framework decode reproductions. Run
  the target's framework+version here to confirm the matrix row before you claim
  a payload works against the target.
- `github.com/doyensec/CSPTPlayground` — Doyensec's CSPT/CSPT2CSRF lab; use it to
  rehearse the CSPT2CSRF chain (`chains.md` §3) and the source→sink gadget
  discovery in a known-good environment.

Never report a decode behavior you only *assumed* from the matrix — reproduce it
against the target's exact version (in the lab or via the live Network tab), then
report.
