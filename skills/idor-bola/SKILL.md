---
name: idor-bola
description: "Hunt IDOR and BOLA by tracing attacker-controlled object references across paths, queries, bodies, headers, cookies, GraphQL nodes, nested resources, mass assignment, stored references, exports, and workers. Use when an endpoint accepts an object or account identifier, list behavior implies a detail route, or two controlled accounts can test horizontal access. Route role or function gates to `broken-access-control` and organization boundaries to `tenant-isolation`."
---

# IDOR / BOLA — object-level authorization

Deep material is split out for on-demand reading (keep this file internalized):
- `references/vectors.md` -- every vector expanded: the bypass ladder, ID-type playbooks (incl. structured/templated ids), the copy-paste bounded enumerator, the IDOR->ATO chain, the full general-class checklist, per-vector oracles.
- `references/second-order.md` -- the stored / second-order class in full: an id accepted NOW and dereferenced LATER in a privileged context (profile/attachment id resolved by an export, PDF, invoice, email or share preview; stored webhook/destination id; batch & async jobs re-checked only at submit; invite/share/delegation ids trusted at acceptance; import/copy source ids; queue runs under a service identity), plus the force-the-dereference table, the two mandatory negative controls, and the rungs.
- `references/patterns.md` -- abstract high-converting arcs (creds-in-source -> vendor/data API -> PII, tenant-header routing + enforcing sibling + cost-amplification twin, dual-authorizer, guest->admin, API-GW->datastore proxy, reset-token->ATO) and GraphQL enumeration (aliasing/batching).
- `references/plays.md` -- the ten plays as they actually ran in **d0x's own 18 reports of this class**, each with the case behind it and its outcome, including the three that resolved Low and the two that came back not-applicable. Read it when you want to know which angle converts, not just which angles exist.
- `references/case-index.md` -- those 18 by play, host, severity and state, with corpus paths and the saturated-host list. Read it at DEDUP, before spending a worker.
- `../_shared/references/output-contract.md` -- where results go: the notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim` dedup key, and the severity enum.
- `../_shared/references/tooling.md` -- what is installed on this host, what is not, and the install line for each missing binary.
- `../_shared/references/safe-ladder.md` -- the read-only -> own/anon -> minimal -> UAT -> proven-impact ladder every proof step climbs. Not "keep it passive": it tells you how far to climb and in what order so verification is safe AND reaches impact. Stopping one rung below proof is the failure it kills.
- `../_shared/references/public-by-default-keys.md` -- when the primitive is a leaked key, SKIP vs PURSUE. A Sentry DSN / Stripe `pk_` / Maps key is not a finding; a Braze / Azure AD / Supabase `sb_secret_` / non-Maps `AIza` key that authenticates a data API is a mass-IDOR waiting to be proven.

## Mission & the one rule

**Prove one cross-account read of the MOST SENSITIVE object the surface exposes -- then ESCALATE THE REACH (cross-tenant / admin / PII-at-scale / cost-amplification / ATO) before you stop.** One adjacent-record read is where the finding STARTS, not where it ends. Climb the safe ladder (`../_shared/references/safe-ladder.md`): read-only first -> your own/anon context -> one minimal cross-object read -> UAT for the risky proof -> reach the payable impact. Stopping one rung below proof -- a bare id-swap you never pushed -- is the failure this skill exists to kill.

- Impact-first. "The endpoint accepts an id" is **not** a finding. A confirmed read of a second, distinct object you do **not** own is the FIRST rung -- then push the reach: is it cross-**tenant**? does the object carry a reset/2FA/session token (-> **ATO**, see vectors.md "IDOR -> ATO")? does the same primitive bill compute to the provider (-> **cost amplification**)? PII at scale?
- Prove the scale, don't hoard it. One cross-account example + the bounded enumerator (5-10 ids, vectors.md) proves the class and its scale; **state the rest by inference, don't dump the table** (rung 3). Bulk PII extraction adds cost and legal risk, not severity -- and nothing will stop you from doing it, so the bound is yours to hold.
- Read-only first (rung 1). Writes only on a synthetic record **you** own, then revert; a write / ATO-completion that would touch a real or foreign object -> ask d0x directly before executing, not attempted (rung 5), state the impact by inference or prove it on UAT.
- Own **depth on the ONE surface you were handed.** Read `targets/<program>/notes/` and `targets/<program>/leads/` first to build on prior passes.

You get **two operator test accounts, A and B** (from `targets/<program>/accounts.md`, which holds their live sessions/cookies/tokens). Two stored sessions replayed via curl -- the two-identity requirement is real, the tool is not.

## "Everything is born from a point" -- the spine

The highest-paid access-control bugs are rarely a bare URL id-swap. They start from a **primitive discovered at a single point** -- a leaked/hardcoded key or credential (in JS bundles or source), an over-broad token, an exposed/mis-scoped endpoint, or a misconfiguration -- and the IDOR is the **escalation** of that primitive into unscoped, cross-account, or mass access.

So there are two first-class discovery vectors -- **rotate BOTH, neither is "the" answer:**

1. **Primitive-driven (highest-converting).** A key/cred/token/misconfig the backend treats as auth. One found string unlocks the whole object space. -> **MINE FIRST:** run/read js-source-to-sink, and curl -s the **raw HTML** (creds often sit inline in `<script>`, which bundle-mining misses) for api_key, bearer, client_id, user_guid, tenant prefixes, internal `*.execute-api` hosts. **Triage the key against `../_shared/references/public-by-default-keys.md` before chasing it** -- SKIP the public-by-design ones (Sentry/Stripe `pk_`/Maps) silently; a key that authenticates a **data / marketing / preferences** API (Braze, non-Maps `AIza`, Azure AD, Supabase `sb_secret_`) is a probable **mass-IDOR waiting to be proven** -> hand to exposed-secrets and prove the object read here.
2. **Identifier-manipulation (classic).** An object id in path/query/body/header/cookie you swap to another user's.

**Fill this frame for every candidate:** primitive (what + where it lives) -> what it unlocks (which endpoint / access) -> impact (mass PII / cross-account / cross-tenant / ATO). The abstract high-value arcs are in references/patterns.md -- recognize them, don't narrow the hunt to them.

## The canonical vectors (one list -- rotate all; detail in references/vectors.md)

| Vector | Swap / abuse |
|---|---|
| Primitive-driven | leaked key/cred/token/misconfig -> broad object access |
| Path id | /users/{id}, nested /orgs/{o}/projects/{p}/files/{f} (test each segment) |
| Query id | ?account=, ?userId=, ?tenant_id= |
| Body id | user_id, owner, recipient_id, to, invoice_id, tenant_id |
| Header/cookie identity | tenant/org/account header as a routing key; a cookie id |
| Tenant/org routing | header carries the org; per-object route uses it with no membership check |
| Cost amplification / entitlement bypass | same tenant header + a garbage org id (even 32 zeros) -> paid LLM/compute billed to the provider, no entitlement check (twin of tenant-routing; often scores higher) |
| Structured / templated id | a "random-looking" id that is really a composite template with tiny real entropy: a fixed prefix + a value that leaks from your own activity (a workflow/run id from your own runs) + a date window + a short random suffix; or a storage key built from org/user/resource ids you already hold. Pin the known segments, enumerate only the small remainder |
| Mass-assignment | set owner_id/tenant_id on create/update |
| JWT / signed token | alg:none, claim-vs-path mismatch, embedded-token leak, self-writable authz claim |
| GraphQL node | swap base64("User:<n>"); introspect hidden fields; batch/alias to enumerate |
| Function-level / vertical BAC | low-priv / **guest** token reaching an admin-only route namespace |
| Unauth API-GW -> datastore | config key -> *.execute-api; SDK validation error = no-auth; read via ReturnValues |
| Second-order / stored | store a reference NOW, let a later surface (export/PDF/invoice/email/share preview/worker/cron) dereference it -> `references/second-order.md` |

**Three vectors are owned elsewhere — recognize them here, then run the owner:**
- The boundary is an org/workspace/tenant, not a single object id → the method is owned by `tenant-isolation` (`../tenant-isolation/references/tenant-vectors.md`). Take the primitive there and prove the cross-tenant read.
- A missing *function-level* decision (role, admin namespace, gateway authorizer, plan gate) → owned by `broken-access-control`. Hand it there and keep the object half here.
- The same missing check exploited in **time** — check-then-act on an object you reference, a single-use token, a limit that should be enforced once → owned by `../broken-access-control/references/race-conditions.md`. Recognition signals only in `references/vectors.md` ("Race / TOCTOU"); the bounded concurrency shape, the oracle and the never-fire rule for financial actions live in the owner file.

## Second-order card — when the boring `200` IS the response

**Signal:** the write stores a **reference**, not a value (`*_id`, `*_ref`, `attachment_id`, `avatar_asset_id`, `template_id`, `channel_id`, `source_id`, `report_id`), and the response is `200 {"ok":true}` with no object in it — while planting a *nonexistent* id returns `404`. The server resolves the id and never checks who owns it.

**Do:** plant B's id from A's session → find the surface that dereferences it later (export, PDF/print view, invoice, emailed copy, share/unfurl preview, batch worker, "run now", cron) → **read the render, not the write**. Then both negative controls (own id → own object; nonexistent id → 404) and the enforcing sibling (canonical direct read of B's object from A → 403).

**Why it outscores a plain id-swap:** the dereference runs in a **privileged / service** context that returns fields no tenant session returns, and the output lands in a **durable artifact** (PDF, invoice, email, public preview) instead of a transient API response.

Open `references/second-order.md` the moment a write stores a reference — that file owns the class for the pack.

## Algorithm

1. **Map** every object-referencing endpoint (path/query/body/header + infer the **detail** endpoint behind every **list**). Build a worklist: endpoint -> object type -> sensitivity. Flag separately every write that **stores a reference** rather than a value -- those are the second-order candidates (`references/second-order.md`), and their proof is a later render, not this response.
2. **Rank** by object sensitivity, test the top first (CRITICAL: reset tokens, 2FA seeds, session/API keys - HIGH: full PII, address/GPS, account email/phone - MEDIUM: order/purchase data, enumerable internal ids - LOW: public-behind-authz).
3. **Establish A/B identity** -- get A's object id and B's id for the same resource type.
4. **Swap** -- in **A's session, put B's id** into A's request; everything else identical.
5. **Confirm via the ORACLE below** (body content, not status).
6. **Negative control (MANDATORY)** -- verify A has NO legitimate access to B's object via the intended flow. This is what separates a real bypass from a shared/public resource; `validation` rejects without it.
7. **Escalate reach** (severity ladder) -> write the lead to `targets/<program>/leads/` in the format in `../_shared/references/output-contract.md` -> STOP.

## Confirmation oracle -- compare BODY CONTENT, not status code

This is the #1 mistake: seeing a 200 and calling it, without checking the body is really the other object's.

| Response to A-session + B-id | Verdict |
|---|---|
| **200 with B's data** (B's fields, distinct from A's) | **CONFIRMED** |
| 200 but same generic / empty / A's own data | NOT a finding -- inspect body |
| **403 / 401** | Authz working -- NOT a finding; rotate angle |
| **404** | Usually authz working -- BUT wrong-tenant 404 while valid-foreign returns 200 = routing miss (id is a lookup key, not an access check) -> keep pushing |
| 400 "missing field" when you blank the id | field read but not authz-checked -> strong signal |
| no-token -> 401/403 | authn enforced, so the bug is **authz** -> the swap is worth pushing |
| fake/nonexistent id accepted | no registry/membership validation -> not cross-checked |

## Rotate & abandon

- **Rotate angle:** 3 failed attempts on one angle (or one payload family) with no new signal -> switch to a different angle on the **same boundary** (the ladder in references/vectors.md). Drop a one-line dead-end note first.
- **Abandon the boundary entirely** -- and move to the next surface -- only once **every** vector above has been tried AND the oracle consistently shows authz enforced (clean 403/401 on foreign ids, enforcing siblings present, no primitive in JS/HTML/config). State plainly "boundary enforced object-level authz against X/Y/Z" and pivot; do not keep re-firing a spent boundary.

## Severity / reach -- how far to push

| Reach demonstrated | Severity |
|---|---|
| One adjacent record you don't own, carrying **PII** (email/phone/DOB/address) | **High** — the class is proven, the scale is inferred (rung 2, two operator-owned accounts). Do **not** downgrade because "only one record was shown" (`../validation/references/severity-anchors.md`, High tier) |
| One adjacent record you don't own, carrying **non-sensitive metadata only** | Medium (lead) |
| Cross-**tenant** / cross-org read | **High** when it carries tenant-scoped business data or PII; **Medium** when non-sensitive metadata only |
| **Admin** object / function-level BAC | High |
| **Cost amplification** -- same primitive drives paid compute (LLM inference, jobs) billed to the provider | **High** -- a documented entitlement gate plus quantifiable billed compute; it scores at or above the bare cross-tenant read |
| **Second-order** -- a later render/export/job returns the other tenant's fields (privileged/service context, durable artifact) | **High**; **Critical** when the artifact is retrievable anonymously or the service-identity render leaks auth material (`references/second-order.md`) |
| **PII at scale** (5-10 distinct victims, bounded via the enumerator) | High / Critical |
| Read/set a credential/reset/2FA/session field -> **ATO** chain (read victim reset token -> complete reset on your session -> log in as victim) | **Critical** |

**Reality check (from real triage):** bare sequential-id BOLA returning **non-sensitive** data only (an org name, a status flag, an opaque counter) is Medium-at-best / often N/A unless **chained to a PII read or a write**. The moment the same swap returns PII it is High on its own — one object each way with two operator-owned accounts is the full proof (rung 2); scale is stated by inference, not by dumping the table. **The Criticals come from chains** (ATO, second-order artifact, PII at scale). Surface the reach in the lead so escalation has material to raise it.

### What 18 of d0x's own reports in this class actually did

Full write-ups in `references/plays.md`; the index with outcomes and saturated hosts in `references/case-index.md`. Four things they show that the ladder above does not:

**The three Criticals share one property, and it is not the bug.** In every one, the identifier needed was **published somewhere anonymous** — a public profile feed returning 30 real ids per page load, a sequential counter, a rendered preference page. The authorization gap itself was ordinary. What made it Critical is that victim selection was free. **Ask where the identifier comes from before asking how bad the endpoint is** — that is the ranking signal for which lead to dispatch.

**Enumerate the endpoint's parameters before writing it up.** The same vendor API produced two reports on one host: an `email=` lookup (per-record, bounded) and a **sequential** `uid=` lookup on the identical endpoint (the whole subscriber base, no victim knowledge at all). One extra parameter is the difference between High and Critical.

**Spend one request looking for the write twin.** Two pairs in the corpus show one defect scoring Low as a read and High as a write — a tenant header that reads batch output versus one that persists into a global catalog, and an RPC proxy whose read half is matched by a mutate half that overwrites another account's billing record.

**Both non-applicable results proved the defect cleanly and failed on the object.** A viewer role renaming a team; a complete basket takeover on a staging host. Rank by object sensitivity at Algorithm step 2 — that step exists for exactly this.

## Safety & operational discipline

- **Scope is a safety boundary, not a hunting filter.** Dial only hosts the program authorized; a victim id, a foreign org id, or an internal host inside the path/query/body/header is always allowed — only the connection target is gated. Nothing refuses a step for you: decide the rung before the request is built. When it would be rung-3-on-prod / other-user PII / a write, **drop to the safe-ladder equivalent (non-PII read on prod, or the full proof on UAT) yourself — that is never a verdict that there is no bug** (`../_shared/references/safe-ladder.md`).
- **Only your two accounts (A/B).** Never brute unknown user ids/emails; source any real victim identifier ethically (the target's own public pages), never guess strangers'.
- **Rate-limit / no DoS.** Enumerate with **bounded, paced** sweeps (5-10 ids, sequential, small delay) -- enough to prove scale, never a flood. Respect single-threaded/fragile servers (one request at a time). If you hit a rate limit, **stop** -- do not hammer; degrading availability is out of bounds even in scope.
- **Reads always OK** (real PII is the proof). **Never modify/delete/corrupt** any data/account/state not yours. Writes only on your own synthetic record, reverted immediately; a write that would hit a real/foreign object is rung 5 -> not attempted: ask d0x directly before executing, or state the impact by inference from the confirmed read.
- **Redact** victim PII and secrets in what you emit; keep object ids in id=<n> form so reproduction/dedup survive.

## Output & handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

Your finding only counts once it is **on disk**. A proof that lives only in a closing summary is permanently lost. Write it to `targets/<program>/leads/` in the format in `../_shared/references/output-contract.md` (funnel, lead fields, the `primitive|host|claim` dedup key, the severity enum), and write a one-line dead-end note before rotating angles.

Route the primitive yourself:

- the IDOR response leaks a key/token -> `exposed-secrets` (triage SKIP vs PURSUE via `../_shared/references/public-by-default-keys.md` first);
- a self-writable Cognito claim, an unauth `*.execute-api` -> datastore proxy, or identity-pool creds -> `cloud-exploitation`;
- about to claim Critical or an ATO -> `validation` re-proves first, then `report-writing`.

**Evidence checklist** (a triager re-proves; thin evidence is rejected — make it copy-pasteable):

1. the **A-authorized** request (method/path/params + which session) and a snippet of A's own object;
2. the **A-session + B's-id** request — identical but the swapped id;
3. a **redacted** snippet proving it returned **B's** object: enough distinct fields to prove ownership without dumping B's PII;
4. that **ids enumerate** — keep ids in `id=<n>` / `id=<uuid>` form so reproduction and dedup survive redaction;
5. the **negative control** (Algorithm step 6) — A has no legitimate access to B's object via the intended flow;
6. the **enforcing sibling** if one exists — "sibling X enforces, vulnerable Y does not" is the single strongest convert argument;
7. the **reach** you demonstrated (cross-tenant / admin / PII-at-scale / cost amplification / ATO), so severity is graded from proof rather than potential.

## False-positive gate

NOT findings -- don't report, don't burn turns: 404/403/401 on a foreign id (authz working) - same-size but generic-error body (compare content) - public profile data - own-tenant access in a multi-tenant app - self-IDOR (your own object via another of your sessions) - enumeration rate-limited before a second victim is confirmed. **Hard gate:** no confirmed read of a second distinct object you don't own + proof A lacks legitimate access = not a finding.
