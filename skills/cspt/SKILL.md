---
name: cspt
description: "Hunt client-side path traversal where an SPA router decodes a route, query, or fragment value and interpolates it into a browser request path. Use when JavaScript shows route parameters reaching `fetch`, dynamic framework routes, missing component encoding, frontend guard bypasses, or the user mentions CSPT. Prove the resulting request and route the final XSS, CSRF, SSRF, authorization, or data-access impact to its owning skill."
---

# cspt — a decoded `../` in a route param is not a finding; the request you land is

CSPT is **the dot-dot-slash the framework hands you.** The browser normalizes a
literal `../` in the URL bar *before* sending, so naive traversal does nothing.
But the frontend router runs `decodeURIComponent()` on encoded components
(`%2F`, `%2E`) *after* the browser parses the URL, then interpolates the decoded
value into a `fetch()` template. The browser re-normalizes at request time —
`../../admin` collapses upward, escaping the intended endpoint and carrying the
victim's session cookie to a destination the attacker controls.

**The divergence — SPA URL bar shows the encoded payload, the Network tab shows
the traversed outbound fetch — is rung 0, a curiosity.** The finding is what that
authenticated request *does*: reach a gated endpoint the frontend was supposed to
hide, land its response in an XSS sink, redirect a state-changing request onto
another action (CSPT2CSRF), or — in a hybrid framework — pivot server-side into
an internal service. Calling the traversed endpoint and demonstrating the
escalation is the deliverable, not screenshotting the divergence and stopping.

**Always chain.** A CSPT that reaches no sink, no gated data, and no internal
service is a Medium at best — and often nothing. CSPT → IDOR, CSPT → stored XSS,
CSPT → CSRF, CSPT → SSRF is the win. Climb the shared safe ladder
(`../_shared/references/safe-ladder.md`): read-only first (land the fetch, read
back the gated JSON) → own/anon context → minimal → UAT for anything
cross-tenant/PII → ask d0x directly before executing for any write on prod. Never stop one rung below
proof; never manufacture a chain that isn't there — if the traversal collapses
back or hits 401/403, say so and rotate.

> **ALREADY REPORTED — reuse the technique, not the report.**
> Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.
>
> For CSPT the next angle is a different route family, a different sink, or the
> server-side handler — not a reworded version of the same chain.

## Read-on-demand references

Keep the trigger map (below) internalized; open a reference when you commit to a
chain.

- `references/decoding-matrix.md` — the per-framework decode internals (which
  component decodes, splat vs. segment matching, the React Router `%252F`
  double-encode bypass / Issue #10814, the SvelteKit `%25`-split block, Nuxt
  `{ decode: true }` opt-in, Next.js server auto-decode), safe-pattern signals,
  how to pin the framework **version**, the lab repos, and the adjacent Next.js
  route-guard bypass CVE-2025-29927.
- `references/chains.md` — the six exploit chains in full: (1) guard bypass →
  gated endpoint, (2) CSPT → XSS sink, (3) CSPT2CSRF (redirect a state-changing
  request with the victim's token), (4) secondary-context → SSRF in hybrid
  frameworks (Next/Nuxt/SvelteKit server), (5) hash-fragment CSPT (invisible to
  server logs), (6) splat/catch-all (literal `../`, no encoding). Each with the
  concrete payload, the read-only PoC, and the safe-ladder rung.
- `references/discovery.md` — the grep methodology (fingerprint → enumerate
  routes → find param→fetch interpolations → list same-origin pivot targets →
  test the payload catalog), the Caido/DevTools divergence capture, and the false
  positives that kill a candidate.
- `../_shared/references/output-contract.md` — where results go: the
  notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim`
  dedup key, and the severity enum.

Also import: `../_shared/references/safe-ladder.md` (how far to climb to reach
impact, safely) and `../_shared/references/public-by-default-keys.md` — if a CSPT
read or a secondary-context SSRF surfaces a client-side key/config, resolve it
against the SKIP/PURSUE table before treating it as a finding (a Sentry DSN /
Maps `AIza` / `pk_live_` is SKIP-silent; a Gemini `AIza` / Braze / IMDS creds is
PURSUE via `exposed-secrets` / `cloud-exploitation`).

## Trigger map — signal → chain → first move

| You see (in the JS / at runtime) | Chain | First non-destructive move | Reference |
|---|---|---|---|
| `useParams()`/`route.params`/`paramMap.get` value in a `fetch()` template, no `encodeURIComponent` | guard bypass → gated endpoint | load `/<route>/..%2f..%2f<gated>`, then the `%23`/`%3f` truncated forms; read the traversed fetch in Network tab | `references/chains.md` §1 |
| Traversed response flows into `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]`/`{@html}`/`innerHTML=` | CSPT → XSS | point CSPT at a same-origin endpoint you can seed with HTML; watch the sink render | `references/chains.md` §2 |
| The vulnerable fetch is a `POST`/`PUT`/`DELETE`/`PATCH` (CSRF-token auto-attached) | CSPT2CSRF | redirect it onto a benign own-account action; confirm the token rode along | `references/chains.md` §3 |
| `[...path]`/`await params`/`getRouterParam(...,{decode:true})` in a Next route handler / Nuxt server / SvelteKit `+server.ts` building an internal `fetch()` | secondary-context SSRF | send `..%2f..%2f<internal-host-or-169.254.169.254>`; read the reflected body | `references/chains.md` §4 |
| SPA reads `window.location.hash` into a fetch | hash CSPT (log-invisible) | payload `#..%2f..%2fadmin`; nothing in server logs | `references/chains.md` §5 |
| Route declared `path="files/*"` / `/:pathMatch(.*)*` / `*param` / `[...path]` | splat/catch-all (literal `../`) | `/<route>/../../admin/users` — no encoding needed | `references/chains.md` §6 |
| A param naming a **path** (`cdnAssetPath`, `templateUrl`, `docPath`) whose fetched body the app then **saves** as the user's asset, filename taken from the same URL | read-then-persist (the `GET` is the sink) | satisfy the extension allowlist with a query-string suffix — `/favicon.ico?x=.pdf` — and watch your own account for the named artifact | `references/chains.md` §7 |
| Next.js target with a route guard / middleware auth | adjacent route-guard bypass | send `x-middleware-subrequest` header (CVE-2025-29927) | `references/decoding-matrix.md` |

## Algorithm

1. **Fingerprint the router + PIN THE VERSION** (`references/discovery.md` Step 1;
   `references/decoding-matrix.md`). The whole matrix row depends on the version — frameworks
   patch this. React Router `%2F` decode, SvelteKit two-stage decode, Next.js
   server auto-decode, Nuxt `{ decode: true }` opt-in each behave differently.
2. **Enumerate dynamic routes and the param→fetch interpolations** (`references/discovery.md`
   Steps 2–3). The vulnerable pattern is a route param / query / hash read, then
   interpolated into a `fetch`/axios/XHR URL **without** `encodeURIComponent`
   (or the router decodes `%2f`/`%2e` before the dev sees it). Prioritize
   splat/catch-all and any `POST`/`DELETE` sink and any server-side handler.
3. **List same-origin pivot targets** (`references/discovery.md` Step 4): admin endpoints not
   gated server-side, weaker API versions (`/api/v1`, `/api/legacy`), endpoints
   that echo input into HTML (XSS fuel), server-side fetch proxies (→ internal
   services). CSPT is **same-origin only** — it cannot dial another domain.
4. **Confirm the divergence read-only** (safe-ladder rung 1): load the payload,
   read the outbound fetch URL in the Caido/DevTools Network tab *after* browser
   normalization, and read back the gated JSON. The oracle is **request URL ≠
   effective endpoint AND the response is data you weren't meant to see** — not a
   status flip on its own. **A 404 is not a negative yet:** when the fetch template
   appends a suffix (`/api/users/${id}/profile`) the traversed request still carries
   it, so fire the `%23` / `%3f` / `%253f` truncated forms before killing the
   candidate (`references/discovery.md` Step 5 and false positives).
5. **Climb to PROVEN impact — pick the chain, do not stop at the divergence:**
   - Rung 1 (read-only): guard bypass → read the gated endpoint's body; hash/query
     CSPT → read the traversed response. That alone proves guard-bypass/IDOR.
   - Rung 2 (own/anon): seed the XSS payload / the CSRF target on an account **you
     created**; fire the sink / the state change against your own object.
   - Rung 3 (prove the scale): one gated record proves the class — do not bulk-enumerate
     other users' objects through the traversal to "show scale."
   - Rung 4 (UAT): if RoE restricts cross-tenant/PII to `*-uat`/`*-oat`, do the
     full cross-tenant CSPT read there; on prod stop at a non-PII gated read and
     state prod-equivalent impact by inference.
   - Rung 5 (write CSPT on prod — a traversal that lands a `POST`/`DELETE` on a
     real destructive endpoint, or reads another real user's data): **pause and
     ask d0x directly before executing**, carrying the exact request.
6. **For hybrid targets, always test the server handler** (`references/chains.md` §4): the
   Next/Nuxt/SvelteKit server receives the *already-decoded* params — traversal
   there reaches internal-only services (no authn, trusts the gateway) and cloud
   metadata → full SSRF. This is the CSPT outcome that most reliably grades
   Critical; hand the SSRF
   escalation to `ssrf-safe`, and if you reach `169.254.169.254`/config →
   `cloud-exploitation`.
7. **Gate the claim and emit the lead** — validate any High/Critical with `validation`, then write the lead to `targets/<program>/leads/` per `../_shared/references/output-contract.md` with the re-runnable divergence + the proven escalation, and rotate to the next boundary.

## Converts? (severity reality — grade honestly)

- **Critical**: secondary-context CSPT → SSRF reaching internal services or cloud
  metadata (Next.js route handler / Nuxt server / SvelteKit `+server.ts`);
  CSPT → stored XSS firing in an admin/privileged viewer.
- **High**: CSPT → stored XSS in another user's session; CSPT → IDOR reading a
  gated/sensitive endpoint with the victim's cookie; CSPT2CSRF that redirects a
  security-relevant state change (email/password/role) onto another action.
- **Medium**: CSPT → IDOR to non-sensitive data; CSPT2CSRF to a low-value action;
  guard bypass reaching an endpoint that returns non-sensitive data.
- **Low / not a finding**: the divergence proven but the endpoint 404s / 401s /
  403s / collapses back to the original (server authz held); self-XSS via CSPT
  with no path to another user. Don't inflate a reachable-divergence into a High —
  climb to the gated read or grade it for what you actually demonstrated.

## Non-destructive rules (the safe ladder, in practice)

- **Read to prove.** A guard-bypass / IDOR / hash CSPT is fully proven by *reading
  back* the gated response — no write needed. Do that first, always.
- **XSS / CSRF proofs use objects you own.** Seed the HTML payload on your own
  account; fire the redirected state change against your own record. Use an
  out-of-band `xss`-style callback if the sink lands in a viewer you cannot
  see (admin/support), and demonstrate on your own submitted content.
- **Write CSPT is rung 5.** A traversal that lands a `POST`/`PUT`/`DELETE` on a
  *real* destructive endpoint cannot always be reverted (the request may complete
  before you can undo it). **ask d0x directly before executing** rather than firing a write CSPT on
  shared infra; prefer proving CSPT2CSRF against a benign own-account action.
- **Minimal, never bulk.** One gated record proves IDOR-via-CSPT; do not walk the
  traversal across other users' object IDs to show scale — state scale by
  inference.
- **Nothing will stop you.** The rung is decided before the chain is fired, by
  reading the ladder — no guard fires afterwards to tell you a line was crossed.
  When a step would be a write on prod or another user's PII, drop to the
  read-only equivalent (non-PII gated read on prod, or the full chain on UAT)
  yourself; if neither reaches it, send the exact request and rollback plan to
  the primary agent so it can ask d0x directly. Continue independent safe angles.
- If a secondary-context SSRF surfaces cloud creds/config, treat them per
  `../_shared/references/public-by-default-keys.md` and flag any live credential
  for rotation.

## Evidence to capture (what makes the lead re-runnable)

Store raw proof under `targets/<program>/notes/` and reference it from the lead;
promote to `targets/<program>/findings/` once `validation` returns a verdict.

- **The divergence, both halves.** The SPA URL bar with the encoded payload AND
  the resolved Network entry after browser normalization — screenshot or HAR.
  One half alone proves nothing.
- **The escalation body**, whichever chain you ran: the gated JSON read back, the
  out-of-band callback for the fired sink, the traversed path + auto-attached
  CSRF/bearer for CSPT2CSRF, or the reflected internal / IMDS response for the
  secondary-context SSRF.
- **Framework + pinned version**, because the whole decoding claim rests on it.
- **A negative control**: the safe sibling route, or the same sink where
  `encodeURIComponent` wraps the param, producing no traversal. Without it a
  triager reads the divergence as a coincidence.
- **Redaction:** victim PII out of the report, object references kept as
  `id=<n>` / `uuid` so the proof still reproduces. The working `notes/` copy keeps
  whatever you need to re-run it.
- **State the rung you stopped at** — e.g. "gated read on prod, rung 1; write
  CSPT withheld (rung 5) and stated by inference."

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- `js-source-to-sink` is the FEEDER into this skill: it fingerprints the router and spots the `param → fetch()` interpolation, then routes here. It does not own CSPT — this skill does.
- The `fetch()` interpolation / route param wasn't found yet → run
  `js-source-to-sink` pass 5 first, then come back here with the route, the param
  source and the resolved fetch template intact.
- CSPT → gated object/admin endpoint → `idor-bola` / `broken-access-control` to
  prove the object-level / function-level authz gap.
- Secondary-context CSPT → internal fetch / any user-URL fetcher → `ssrf-safe`;
  IMDS/metadata/config reached → `cloud-exploitation`.
- CSPT surfaced a raw key/secret in a traversed response → `exposed-secrets`.
- Cross-tenant CSPT read → `tenant-isolation`.
- About to claim Critical/High → `validation` re-proves. Confirmed bug →
  `report-writing`.
