---
name: broken-access-control
description: "Hunt missing or incorrect authorization across functions, roles, admin namespaces, plans, entitlements, gateway versions, tokens, presigned resources, uploads, realtime channels, revoked users, and edge-to-origin differentials. Use when an endpoint trusts a client-supplied identity or authorization value, a UI-only gate exists, a 401 or 403 may differ across routes, or equivalent APIs enforce different checks. Route object-level and tenant-specific cases to their dedicated skills."
---

# Broken access control

Prove **one** server-side authorization decision is missing or inconsistent — across actors, interfaces, lifecycle states or tenants — then climb to the payable impact. Discovering a reachable route, header or token is never the finding.

Two sources feed this skill. The **cards** are methodology: how to recognise a vulnerable endpoint *type*, the oracle ladder that confirms it, the conversion verdict. No card names a real route — you find the match on your target. The **plays** are the same class seen through 29 of d0x's own reports, with what each one converted to.

The class is one question asked in four places:

| | the question | the failure |
|---|---|---|
| **object** | may this caller touch *this* object? | BOLA / IDOR |
| **function** | may this role call *this* endpoint? | admin namespace reachable |
| **entitlement** | has this account *paid* for this? | free tier reaches paid capability |
| **credential** | is this token *valid*, or merely *present*? | decorative credential |

The fourth is the one hunters miss, because a request that succeeds while carrying a credential looks authorized.

## Boundary with the adjacent skills — own the hybrids

`idor-bola` owns the **pure** case: the function-level check works, the only gap is an unchecked object id, and swapping the id reads a sibling object. **Everything else is this skill, including function+object hybrids** — and the function-level half is usually the higher-severity half, so do not punt it.

Hand to `idor-bola` only when the residue is literally *same endpoint, same role, different id, no ownership check*, with the function-level angle already stripped.

Two vectors leave this skill for `tenant-isolation`, and only when the boundary crossed is an **org or tenant** rather than a role: tenant/org-header routing (card 4) and the self-writable identity-provider attribute (card 5). Cards 4 and 5 below are recognition-only.

## Safety, with nobody watching

There is no human in the run. The gate is a rule, not a person:

- **Read-only first** — negative control, then a non-PII read that proves the primitive.
- **Two accounts you control**, or the anonymous state when that *is* the vulnerable state.
- **Prove the scale, never hoard it** — one representative cross-boundary read proves the class; a bounded 5–10 record read proves it is systemic. Never a table dump.
- **Writes only on objects you own**, sentinel values, reverted immediately, appended to `writes.jsonl`.
- **Anything touching a third party's object → ask d0x directly before executing.** Send the exact request, affected state and rollback plan to the primary agent. This is an interactive approval step, not a terminal lead state.

**Public inputs are not leaks.** A web-client api key, a Firebase web key, an unauthenticated guest-login key, an identity-pool client id — these ship to every browser by design. Do not report them as secrets. They are legitimate **inputs** to the technique here; the finding is the missing authorization behind them.

---

## Start here: find the enforcing sibling

**The highest-yield move in the corpus, and both a discovery technique and the strongest line a report of this class can carry.** Five of the 29 reports turn on it, and it is the last rung of nearly every oracle ladder below.

> **Shape.** When an endpoint answers you, look for its neighbour that *refuses* you — same service, same resource, same plane, correct control already applied. Then you are not arguing that a check should exist. You are showing the team their own check, applied here and not there.

Enumerate siblings before you enumerate ids: every verb on the resource, every operation in the schema, every adjacent path segment, every version, every sibling service on the plane. A non-uniform column is the finding.

Cases in `references/plays.md` §1 — a config resolver that refuses every caller-supplied name beside two that answer any of them · two cart mutations that resolve ownership and a third that does not · two operations on an identical path returning `403` while two others return `200` unauthenticated · a gateway whose image endpoint enforces entitlement while its LLM and video endpoints do not.

---

## The arsenal

Each card: recognise the endpoint **type** → attack → oracle ladder → what it converts to.

### 1 · Any-valid-token reaches an admin namespace

An admin or back-office route family enforces *authentication* and never re-checks *role*, so any token the app will mint — including a credential-free guest one — is accepted.

- **Recognise:** an admin/back-office/console/internal route prefix found in the JS or source maps that the user UI never calls; these groups commonly span 20+ sibling routes. Plus any unauthenticated path that returns a *usable* bearer — a guest or "public" login, a key in the bundle that mints a token, a demo session.
- **Attack:** mint the lowest-privilege token the app offers, then replay it against the admin namespace. No role was ever proven.
- **Oracle:** no token → `401`; guest token on a normal route → `200` (baseline: the token is valid); the same token on an admin route → `200` with data (role never checked); a sibling admin route that *does* enforce → `403` (the gap is per-route, not a globally open door).
- **Edge in the way?** Recover the origin — an SPF record is the highest-yield source — and dial it directly. Full ladder in `references/role-matrix.md` §1.
- **Converts:** **Critical** when the group returns cross-user PII; **High** for non-PII privileged data. The reachable route alone is not a finding.

### 2 · Dual-authorizer gateway

A second or internal API gateway sits behind the app. Most routes require IAM request signing, but a JWT authorizer was left attached to a few, and the function behind them does no ownership check.

- **Recognise:** the JS reveals a second gateway host distinct from the main API. Probe its routes with a plain id token: most return an IAM signing error, a few return `200`. Among those, find one naming a source object owned by another account **and** a caller-controlled destination — a copy, clone, export or share action.
- **Attack:** resolve the victim's account id from an enumeration route, invoke the copy route with their object as source and your identity as destination, then read the result through the main API.
- **Oracle:** the route accepts your JWT rather than returning the IAM error, and acts on an id you do not own; a sibling internal route still returns the IAM error → the authorizer was left on by mistake.
- **Converts:** **High** with the ownership gap plus a caller-controlled destination; **Medium** for the authorizer gap alone. Function+object hybrid — own it here.
- Full method: `references/role-matrix.md` §2. Gateway and datastore mechanics: the `cloud-exploitation` skill.

### 3 · Body-field identity spoof

The endpoint carries the acting user's identity in the **body**, and the handler trusts that field instead of binding to the token's subject.

- **Recognise:** an authenticated write whose body names a user or owner. Lives in feedback and rating, comments, profile and preferences, report-abuse, share and invite, on-behalf-of actions.
- **Attack:** replay your own authenticated request with that field swapped to a second account you control.
- **Oracle:** no token → `401` (signature enforced); own token + own id → `200` (baseline); own token + the other id → `200`/`201` (bound to the body, not the token); a well-formed nonexistent id → no not-found (no registry check); an empty id → `400 missing field` (reads the body id, never cross-checks the subject); unschemaed extra fields accepted → metric poisoning.
- **Converts:** **Medium** — attribution and metric poisoning. Raise it only by proving the read side or a downstream routing effect such as a moderation queue. Object half → `idor-bola`.
- Full method: `references/graphql-api.md` §1.

### 4 · Tenant or org header as a routing key — *recognition only*

An endpoint takes the acting tenant from a request header and uses it as a lookup key without verifying membership. The *list* endpoint is correctly scoped; per-object endpoints trust the header.

- **Recognise:** a header selecting org or tenant context; per-object routes echoing a presigned URL or a storage key shaped `{orgId}/{userId}/{resource}` — that shape both confirms cross-tenant reach and predicts sibling ids. Low-entropy ids make enumeration trivial.
- **Converts:** **High** when the foreign-tenant response carries tenant-scoped business data or PII; **Medium** for non-sensitive metadata; **Critical** at mass PII. The cost-amplification twin also converts High and routes to `resource-abuse` for the metering angle.
- Then run the `tenant-isolation` skill, which owns the attack.

### 5 · Self-writable identity attribute → forged tenant claim — *recognition only*

The access token carries a scope letting the user call the identity provider's own API. If a tenancy-bearing custom attribute was not marked admin-write-only, the user overwrites it to a victim tenant's id, re-authenticates, and reads across the boundary.

- **Recognise:** a token carrying an identity-provider self-administration scope; a backend authorizing tenancy from a custom claim. Pool and client id come from the token itself; the victim tenant id leaks via CDN asset paths, other users' tokens, same-domain auto-assignment, or a public members route.
- **Oracle:** the attribute update returns `200` on an authz-bearing attribute; the re-minted token carries the forged value; the tenant-scoped endpoint returns another tenant's data. **The `200` alone is not a finding.**
- **Safety:** the write is on **your own** profile — allowed, and reverted immediately. Write your own second org's id by default. A real victim org id belongs on a UAT host; on production it requires d0x's approval before execution.
- **Converts:** **Critical**.
- Mechanics: the `cloud-exploitation` and `tenant-isolation` skills.

### 6 · JWT `alg:none` and claim-vs-path

- **Trigger:** identity travels in a decodable JWT; a mobile or legacy route may only *decode*, never *verify*.
- **Ladder:** (a) `alg:none` with an empty signature; (b) RS256→HS256 confusion, re-signing with the public key as the HMAC secret; (c) **claim-vs-path mismatch** — submit a token whose subject disagrees with the path or body id and see which one the server trusts; (d) `kid` traversal or injectable `jku`/`x5u`.
- **Oracle:** the forged or mismatched token returns another user's data; the server never rejects the tampered signature.
- **Converts:** **High/Critical** when it performs another user's action. Recurrent mobile chain: an `alg:none` id token accepted while a secondary signed header is satisfied from a key recovered from the decompiled app, leaving the object id as the only remaining control. See `references/invitation-identity.md` §A1.
- Token **forgery** itself belongs to the `auth-flow-bypass` skill. What stays here is the authorization consequence: which identity the server trusts once the token is accepted.

### 7 · API-version downgrade

- **Trigger:** a versioned API where authorization middleware was added in the newer version.
- **Technique:** replay the same authenticated request against `/api/v1/`, `/api/`, `/api/legacy/`, or strip the version prefix; swap the version in nested paths.
- **Oracle:** v2 → `403`, v1 with an identical body → `200` with the restricted data. See `references/graphql-api.md`.

### 7b · The 403-bypass ladder — path and method

The component making the authz decision and the component dispatching the request disagree about **what the request is** — its path, or its method.

- **Recognise:** any route returning `401`/`403` at an edge or in middleware while an origin behind it serves the same resource.
- **Path transforms**, one at a time: `/admin/` → `/admin` → `//admin` → `/./admin` → `/admin/.` → `/admin;/` → `/admin%2f` → `/%2e%2e/admin` → `/aDmIn` → `/admin.json` → `/admin?` → trailing dot → `/admin%20` → `/admin/..;/`; plus routing headers `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`.
- **Method transforms:** read verbs on a write-only handler and the reverse, then `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, `?_method=`. What pays is an edge rule bound to the **verb** — one blocked, another not, or a delete reached through an override. **CVE-2023-30845** is exactly that at the gateway layer.
- **Next.js CVE-2025-29927:** send `x-middleware-subrequest: middleware` on the gated path. Fingerprint the version from the static chunk banners first.
- **Oracle:** identical request, one transform, `403` → `200` **with the restricted body**, plus the enforcing sibling. A `200` returning the login page or SPA shell is not a bypass — compare bodies. A `HEAD` `200` with `Content-Length: 0` proves routing, not disclosure.
- **Safety:** read verbs are free. A mutating verb — or an override resolving to one — against a real object requires d0x's approval before execution; prove it instead on a well-formed nonexistent id, where the handler 404s *after* the verb cleared the control.
- **Converts:** grade by what the bypassed route returns; the transform itself is not a finding. `405` differentials and `OPTIONS`/`Allow` enumeration are informative.
- Full method, both dimensions and the per-framework override matrix: `references/role-matrix.md` §1b.

### 7c · Edge path-filter desync

Card 7b bypasses an *authorization* decision. This bypasses a *path filter*: an edge enforces an allowlist the origin never re-checks, because the edge matches a regex over raw bytes while the origin parses them with a richer grammar — path parameters, selectors, format extensions, percent-decoding, dot segments — and resolves them to the same resource.

- **Recognise:** two tiers visible in the headers; one path answering in a different dialect than the rest of the app; an origin whose grammar is richer than a path.
- **Attack**, one transform at a time on one blocked path: an allowed extension appended after the real one; `;` path-parameter smuggling; `..;/` climbing (patched in modern Jetty — fingerprint first); unanchored-regex suffix; encoding variants, usually only as a second rung; raw-path proxying prefixes.
- **Oracle — response SIZE, not status.** Measure three baselines first: the origin's `200`, the edge's block page, and an allowed-extension nonce the origin 404s. Classify every probe by which cluster its byte count lands in. Edge denials are all the same size. `Server` is rewritten by the edge on both paths and proves nothing. Send everything with `--path-as-is` — curl silently resolves a literal `..` and turns a landed bypass into a recorded failure.
- **Converts:** reaching the origin is not a finding on its own — a JSON tree of a page's own public content is working as designed. Grade by what it unlocked and route it onward. Where the program's vendor names the edge as the security boundary, the bypass itself is defensible; elsewhere lead with the data.
- Full method: `references/edge-filter-bypass.md`.

### 8 · GraphQL introspection and alias-batch

- **Trigger:** a reachable GraphQL endpoint; fields or mutations absent from the UI.
- **Technique:** introspect to enumerate the real schema; find fields the UI hides; test whether resolvers enforce the viewer or merely look up by id; alias-batch to enumerate many ids in one request, which also bypasses per-request rate limits.
- **Oracle:** introspection returns the schema when it should be disabled; an aliased batch returns multiple other-user objects. See `references/graphql-api.md`.

### 9 · Race / TOCTOU

The server reads a counter, decides, then writes, with no lock across the two, so N concurrent copies of the same request all pass the check.

- **Recognise:** any single-use or limited resource whose second use returns a **semantic** denial — `409`, already redeemed, limit reached — rather than a permission error.
- **Attack:** parallel requests as the cheap probe, then last-byte synchronisation over HTTP/1.1 with the shipped racer.
- **Oracle:** N successes where the second should have been denied, **plus** a follow-up read where state is off by exactly the number of extra winners, **plus** the sequential control returning `200 409 409`. One success is not a race; a `500` from a lock timeout is not a race.
- **Safety:** 2–3 concurrent, your own object, reverted. **Financial actions require d0x's approval before execution — do not fire.**
- **Converts:** **Medium** for coupon, seat or vote reuse; **High** when the extra winners become credit, a defeated plan limit or a non-decrementing MFA counter; **Critical** only with a chain.
- Full method: `references/race-conditions.md`.

### 10 · Request smuggling / desync

Front end and back end disagree about where a request ends, so bytes the edge never inspected are parsed by the origin as a request, with none of the edge's enforcement applied.

- **Try cards 7b, 7c and the origin bypass FIRST.** They reach the same impact with no shared-socket risk. Desync is the fallback when the edge holds.
- **Attack — safe form only:** the timing differential, a self-contained probe whose declared length leaves the back end waiting for bytes the front end never forwards, on a fresh connection closed immediately.
- **Oracle:** probe TTFB minus control TTFB above roughly 5 s with **both** controls fast, reproduced, and disappearing when the chunked header is removed. A hanging probe can also mean the front end blocked — disambiguate with the other direction.
- **Hard line:** residual bytes are prepended to the next request on a pooled socket belonging to a real user. Queue poisoning, request capture and serving your response to someone else **do not happen on production** — timing oracle only, then state impact by inference.
- **Converts:** timing-only is a lead, not a finding, in most programs. **Medium/High** when paired with a named edge-enforced control you can show the origin ignores.
- Full method: `references/request-smuggling.md`.

### 11 · Realtime authz

WebSocket, gRPC-web or SSE: the transport authenticates once, then the channel, topic, tenant or object id travels inside the frames where no ownership check runs. The REST twin of the same data is usually correct.

- **Recognise:** socket, event-source or gRPC-web constructors in the bundle; generated protobuf service stubs; a first frame shaped like a subscribe naming a channel that embeds an org id.
- **Attack:** replay account A's upgrade, then send a frame naming account B's channel or object. Also: a cross-origin upgrade with no origin check, and a token in the query string.
- **Oracle:** the frame you receive carries **the other tenant's field values**, not merely a switching-protocols response or a subscribe acknowledgement. The enforcing sibling is REST returning `403` for the same session.
- **Converts:** **High** for a proven cross-tenant read with distinct PII; **Critical** only with a broadcast channel or a privileged write frame; **Low** for a token in the query alone.
- Full method: `references/realtime-authz.md`.

### 12 · Entitlement never checked

A valid token is not a paid token.

> **Shape: the UI enforces it and the API does not.** Whenever the interface shows a limit, a plan gate, a credit balance or a premium badge, go find the endpoint behind it and call it directly.

- **Oracle:** the free identity performs the gated action; the meter does not move; the enforcing sibling on the same platform returns a not-entitled error.
- **Converts:** it depends on the frame, and getting this wrong cost a Critical in the corpus. If the impact is **cost to the vendor**, this is metering — lead with the cost and route it to `resource-abuse`. If the impact is **reaching another identity's data**, it stays here. See `references/plays.md` §6.

### 13 · Gated on state instead of identity

A write refuses you with a **business-state** error rather than `401`/`403`. It never checked who you are; it checked whether the object is in an editable state.

- **Oracle:** the unauthenticated write returns a state error, not an auth error; the same call on an object *in* an editable state succeeds.
- **Prove it on your own object.** A corpus report inferred this write rather than demonstrating it and was capped at informative for exactly that. See `references/plays.md` §9.

### 14 · Server-side relay that substitutes a secret

A service fetches a caller-named URL and substitutes a stored credential into the request before sending.

- **Recognise:** a forward, proxy or connector endpoint taking a caller-supplied endpoint, method, headers and body; a placeholder string in the request that the service replaces.
- **Two paths, failing differently:** *exfiltration* — the destination is caller-chosen, so the secret goes to any host you name; *relay* — point the destination at the provider's **genuine** token URL and the upstream response, containing a live token, is relayed back. **The relay path survives an allowlist on the destination.**
- **Converts:** **High**. Also test and *state* whether internal addresses are reachable — see `references/plays.md` §10 for the "not claimed" section that made one such report credible.

### Product CVEs worth fingerprinting

When the target runs the product, the technique above overlaps a known CVE — prove it on the live instance: Confluence Data Center **CVE-2023-22515**; FortiOS/FortiProxy admin-interface bypass **CVE-2022-40684**; F5 BIG-IP iControl REST **CVE-2021-22986**.

### Routing — open the reference when the shape appears

Open `references/race-conditions.md` when a limited resource answers its second use with a semantic denial. Open `references/edge-filter-bypass.md` the moment an edge refuses a path, extension or selector a backend behind it plausibly still serves. Open `references/request-smuggling.md` **only after** 7b, 7c and the origin bypass have failed, and read its safety line first. Open `references/realtime-authz.md` the moment the target speaks WebSocket, gRPC-web or SSE — that interface is usually where the per-object check was never written.

**The lifecycle split.** Session lifecycle — fixation, logout, revocation, password or 2FA change invalidation — belongs to `auth-flow-bypass`. `references/lifecycle-persistence.md` owns access outliving **role, seat or grant removal**: the removed member, the downgraded plan, the revoked token, the deprovisioned account. If the credential should have died because the *session* ended, it is theirs; if because the *authorization* ended, it is ours.

---

## Algorithm

1. **Build the access matrix** from `accounts.md` — owner, admin, member, read-only, guest, removed, disabled, unverified, API token, anonymous.
2. **Map privileged actions and identity carriers** — method and path, GraphQL operation names, body identity fields, tenant headers, token scopes, API version, every additional gateway host in the JS.
3. **Negative control.** The no-auth, wrong-role or wrong-tenant call that denies. This is what makes the bypass a finding.
4. **Baseline.** Do the action as the allowed actor on synthetic data.
5. **Replay minimally** with the restricted actor, anonymous token, forged claim, older version or hidden operation.
6. **Compare interfaces** — web, mobile, REST, GraphQL, internal gateway, clone/import. Find the sibling that enforces.
7. **Confirm server-side.** A disabled button is irrelevant; the response body and a follow-up canonical read are what matter.
8. **Demonstrate scale** — bounded, 5–10 records, read-only, then stop.
9. **Write the lead** in the `templates/lead.md` format, with the control block filled.

---

## Confirmation oracles

**Strong:** a guest or credential-free token reaching an admin route · an internal gateway accepting your JWT while a sibling returns the signing error · own bearer plus victim body id → `200`, empty body id → `400` · a victim tenant header returning data while a garbage tenant id shows no validation · a forged or mismatched token returning another user's data · v1 succeeding where v2 denies · the same path and credentials giving a different outcome purely as a function of the **method**, restored when the override header is removed · an aliased GraphQL batch returning multiple other-user objects · a read-only token performing a write · a removed user's token still working · N concurrent successes with state off by exactly N−1 and the sequential control denying · an edge-blocked path landing on the **origin's** byte count once a transform is added · a realtime frame carrying another tenant's field values while REST returns `403` for the same session · **a sibling endpoint returning `403` while the vulnerable one succeeds — the single strongest convincer, always find it.**

**Weak:** a hidden UI button with the server still returning `403` · one public field · same-tenant shared access with no documented restriction · `200` with no state change.

**Not findings:** public data · intended collaboration · self-actions with no privilege gain · a client-only toggle with no server-side confidentiality promise · proof requiring another user's session or inbox · `404`/`403` on the swapped id, which is authorization working.

---

## Severity

- **Critical** — cross-tenant control, admin or owner takeover, password-reset ATO, large-scale PII, payment authority, persistent access after removal.
- **High** — role escalation, dual-authorizer action on another account, cross-tenant read of sensitive data, guest-to-admin data read, sensitive export, token or session operation, billed cost amplification.
- **Medium** — restricted action on owned or synthetic data, write-only body-field spoof, limited permission bypass.
- **Low** — weak metadata exposure.

**Do not inflate.** A write-only body-field spoof caps at Medium. A reachable route, header or token with no proven cross-boundary effect is not a High. The enforcing sibling and the persisted cross-boundary read are what earn the grade, and the `validator` verdict binds whatever you propose.

### Bounding it — this is why these reports land

**Enumerability decides bulk versus per-record, and you must state which:**

| id shape | reachable population |
|---|---|
| dense sequential counter | everyone, no prior knowledge |
| small integer also published elsewhere in the product | the entire user base |
| random UUID, not enumerable | one victim, and only with the id |

One corpus report says it outright: *"the identifier is a random UUID, so exploitation requires knowledge of the target id, bounding this to a per-record disclosure rather than a bulk leak, hence Medium."* Writing that sentence yourself stops a triager writing it for you, less generously.

**Write a "not claimed" section.** List what you tested and ruled out. Ruling out the bigger finding is what makes the smaller one credible.

**Count the records** when it is a leak — the count is what makes it Critical instead of Medium. **Repeat the control after the attack**, so the outcome is not an artefact of ordering, caching or throttling.

---

## Evidence checklist

A triager re-proves. Capture, in order: the **negative control** that denies · the **actor matrix** · the **exact request** · the **expected-restriction source** — a UI label, docs, or the **enforcing sibling** that denies the same actor · the **actual result** with a follow-up canonical read proving persistence · **bounded scale** for hybrids · **cleanup status** for any synthetic write · a **hybrid note** if a function gap combines with an object reference.

Redact victim PII; keep ids in `id=<n>` form so reproduction and dedup survive redaction. Keep the lead title stable — the dedup key is `primitive|host|claim`.

---

## Handoffs

**A handoff is a self-invocation.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same lead, carrying the raw primitive intact. Nobody else picks it up.

`idor-bola` for the pure id-swap residue only · `tenant-isolation` for cards 4 and 5 · `cloud-exploitation` for gateway, identity-pool and datastore mechanics · `auth-flow-bypass` when the token is **forgeable** rather than merely over-accepted, and for session lifecycle · `exposed-secrets` when a body or header key turns out to be a real server secret rather than a public client id · `resource-abuse` when the bypass amplifies cost or defeats a meter · `deserialization-hunting` when privileged state rides in a serialized blob.

High and Critical candidates never get a report written by the hunter: return `validation_needed` and the `validator` agent decides.

---

## Dedup — reuse the technique, not a closed report

Before calling anything new, check `ledger/reported.md`, then the corpus at `~/Desktop/skills/personal-corpus/`, then this target's own `findings/`. Key: `primitive|host|claim`.

Same primitive on the same host is **closed** — rotate to a different actor, tenant or interface. **The same technique on a new host is a new finding**; that is how one play converts repeatedly, and killing it is the most expensive mistake in the dedup step.

`references/case-index.md` lists which hosts in the corpus are already saturated.

---

## Reference material

**Method, deep:**
- `references/role-matrix.md` — guest-to-admin, dual-authorizer, origin bypass, demonstrate-scale, hybrid ownership, and §1b: the 403-bypass ladder in both dimensions with the per-framework override matrix
- `references/edge-filter-bypass.md` — the six-rung path-filter desync ladder and the size-differential oracle
- `references/race-conditions.md` — the whole race pack, including MFA counters and metered actions
- `references/realtime-authz.md` — WebSocket, gRPC-web and SSE authorization
- `references/request-smuggling.md` — the safe timing oracle only
- `references/graphql-api.md` — introspection, alias-batch, resolver authorization, version downgrade
- `references/invitation-identity.md` — invite, verification, recovery, SSO and SCIM identity gaps
- `references/lifecycle-persistence.md` — access outliving role, seat or grant removal
- `references/workflow-state.md` — workflow-state and clone/import bypass
- `references/public-exposure.md` — presigned-URL scope failure and public exposure
- `references/case-patterns.md` — worked patterns from disclosed research

**Evidence, from d0x's own reports:**
- `references/controls.md` — the control matrix: what each control discriminates, with the exact requests
- `references/plays.md` — the ten plays with the corpus case behind each, and the two frames that lose value
- `references/case-index.md` — all 29 reports by play, host and outcome, with corpus paths and the saturated-host list

## Verdicts

`finding` only with a demonstrated cross-boundary effect. `primitive` when the check is provably absent but no victim object was reached — file the gadget and state exactly what is missing. When the boundary needs a role or entitlement not held, ask d0x once for it. When proof would write to a third party's object, the primary agent asks d0x directly before execution with the exact request and rollback plan.
