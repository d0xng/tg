---
name: tenant-isolation
description: "Hunt cross-tenant, cross-organization, and cross-workspace isolation failures where a tenant identifier controls routing without enforcing membership. Use when an organization, workspace, account, or tenant ID appears in a header, token claim, path, body, GraphQL variable, presigned key, cache key, or writable profile attribute. Route single-object horizontal access to `idor-bola` and role, admin, or plan gates to `broken-access-control`."
---

# Tenant Isolation

The tenant boundary is the highest-value trust line in a multi-tenant SaaS: one
break reads *every other org's* data, not one adjacent record. This skill is the
dedicated cross-org / cross-workspace / cross-account playbook — the tenant-scoped
subset of the IDOR class, expanded with the recognition / oracle / attack methodology
for each tenant vector: header-routing read IDOR, the entitlement/cost-amplification variant, the Cognito
writable-custom-attribute takeover, the dual-authorizer gateway, and the
guest/anon→admin surface.

Use **this** skill when the boundary is an **org / workspace / tenant** — the id in
the path/header/claim selects *whose data you get*, and one swap crosses into a
different customer. Two boundaries are owned elsewhere:

- A single object you own vs another user's — not an org boundary — is `idor-bola`'s
  object-id ladder (`../idor-bola/references/vectors.md`).
- A role/admin/gateway/plan gate rather than a tenant gate is `broken-access-control`
  (`../broken-access-control/references/role-matrix.md`).

## Read-on-demand references

- `references/tenant-vectors.md` — the vector arsenal as recognition + oracle + attack
  methodology. **This skill owns §1** (org/tenant-header-as-routing-key read IDOR) and **§2**
  (the entitlement/cost-amplification twin). §3 dual-authorizer, §4 guest/anon → admin-namespace
  + WAF-origin, and §5 body-field spoof are recognition cards that route to
  `broken-access-control`.
- `references/cognito-takeover.md` — Cognito self-writable custom-attribute
  (`custom:aId`) cross-tenant takeover, end to end, GetUser→UpdateUserAttributes→
  re-auth→cross-tenant read→REVERT. This skill owns the tenant chain; the AWS
  `X-Amz-Target` API mechanics are owned by `../cloud-exploitation/references/cognito.md` §5c.
- `references/cache-deception.md` — **the pack's owner of web cache deception**: the
  edge-caches-by-extension vs origin-normalizes-the-suffix disagreement, the full payload
  family (`/account/foo.css`, `/account;.css`, `%3B`, `%23`, `%00`, `%0A`, `..%2f`, double
  extension, trailing slash), the `X-Cache`/`CF-Cache-Status`/`Age` oracle with real observed
  output, and the rung-2 seed-your-own-page-then-fetch-it-anonymously proof. Open it the moment
  a cache header appears on an authenticated page. Also carries the recognition block for the
  sibling class, unkeyed-header cache **poisoning** (denial variant owned by
  `../resource-abuse/references/cache-poisoning-denial.md`).
- `references/oracles-and-leaks.md` — the 404-routing-miss vs 403-authz oracle, the
  enforcing-sibling convincer, the garbage-tenant-id test, and every victim-org-id
  leak oracle (avatar CDN paths, JWTs, presigned storage-key prefixes, public team/directory endpoints).
- `../_shared/references/output-contract.md` — where results go: the notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim` dedup key, and the severity enum.
- `../_shared/references/tooling.md` — what is installed on this host, what is not, and the install line for each missing binary.
- `../_shared/references/safe-ladder.md` — the read-only-first → own/anon → minimal →
  UAT → direct approval before risky execution impact ladder. Import it; do not reinvent a "keep passive" rule.
- `../_shared/references/public-by-default-keys.md` — before treating any key you find
  as leverage, resolve it here (an `x-api-key` that is a public client_id is *not* the
  bug; the missing tenant check is).

## Mission & the one rule

**Prove ONE cross-tenant READ of another org's most sensitive object — or one
cost/entitlement action billed to a victim tenant — then STOP.**

- **A write-200 alone is N/A.** `UpdateUserAttributes → 200 {}`, a body-spoof write → 201,
  a cross-tenant copy → 200 prove nothing by themselves — the backend may re-validate the
  tenant per `sub` on the next read. The finding is the **end-to-end cross-tenant READ**
  the write unlocks (or the paid compute the tenant swap drives). Never stop at the write.
- Impact-first. "The endpoint takes an org header" is not a finding. A confirmed read of
  another tenant's PII/objects, or paid LLM inference billed to a foreign org, is.
- Minimal proof: one foreign-tenant object + evidence the tenant id enumerates. Never
  bulk-dump another org's users — one cross-tenant read plus an enforcing sibling proves
  the class; the table dump is the destructive version — nothing blocks it, and the program
  penalizes it. Scale is stated by inference (`../_shared/references/safe-ladder.md` rung 3).
- Writes only on a record/attribute **you own** (your own Cognito user's `custom:aId`,
  your own feedback object) and **revert immediately**. That write is **rung 2** — it
  mutates your account, never the victim's (`../_shared/references/safe-ladder.md`).

You get **two operator-controlled tenants, A and B** (two orgs/workspaces, ideally two
accounts each — from `targets/<program>/accounts.md`). The cross-tenant read is
A's session reaching B's org data. If you only have one tenant, seed a second (self-signup;
`UserConfirmed:true` lowers the bar); if neither is possible, ask d0x once for the
missing tenant account and continue every independent safe angle.

## Map the tenant identifier first

Before swapping anything, locate where "which tenant" is decided. It is almost never the
URL alone:

| Location | Examples |
|---|---|
| URL path segment | `/orgs/{orgId}/...`, `/accounts/{accountId}/...`, `/workspace/{wsId}/...` |
| Request header | `X-Org-Id`, `x-org-id`, `x-tenant`, `X-Account-Id`, `x-workspace` (value may be a plain uuid or a composite uuid+org/domain) |
| Body field | `{"orgId":...}`, `{"tenantId":...}`, `{"accountId":...}`, `{"userId":...}` (or any owner field) |
| JWT claim | `custom:aId`, `custom:domain`, `org`, `tid`, `account_id` (server trusts the claim) |
| GraphQL variable | `organization(id:...)`, `workspace(id:...)`, node `base64("Org:<n>")` |
| Presigned storage key | a storage-key prefix that embeds the tenant id (`{orgId}/{userId}/{resourceId}/...`) — leaks the tenant layout |

Record each to `targets/<program>/notes/tenant-surface.md`: `endpoint → where the tenant id lives → object type → sensitivity`.

## The canonical tenant vectors (rotate ALL — detail in references)

| Vector | The break | Ref |
|---|---|---|
| **Tenant header = routing key** | server uses `x-...-org-id` as a lookup key, never checks membership → foreign org read | tenant-vectors §1 |
| **Entitlement / cost amplification** | same missing check → drive paid LLM inference / quota with a foreign (even all-zero) org id, billed to victim | tenant-vectors §2 |
| **Cognito writable custom attr** | `aws.cognito.signin.user.admin` scope → `UpdateUserAttributes custom:aId=<second-org-you-own>` → re-auth → forged-claim JWT → cross-tenant read | cognito-takeover |
| **Dual-authorizer gateway** | internal `*.execute-api/<stage>` where a couple of routes accept a plain Cognito JWT (rest demand IAM SigV4) + zero ownership check on the path account/project id | tenant-vectors §3 (method owned by `broken-access-control`) |
| **Guest/anon → admin namespace** | credential-free guest token accepted on an admin-namespace route group; WAF-origin bypass via SPF | tenant-vectors §4 (method owned by `broken-access-control`) |
| **Body-field identity spoof** | handler trusts a `userId`/owner identity field in the body over the Bearer `sub` (write-side; escalate to a read to convert) | tenant-vectors §5 (method owned by `broken-access-control`) |
| **Mass-assignment of tenant** | set `orgId`/`tenantId` on a create/update to plant an object in another tenant | tenant-vectors §5 (general vector owned by `idor-bola`) |
| **GraphQL org node** | swap `base64("Org:<n>")`; introspect org fields not in UI; batch to enumerate | `../idor-bola/references/vectors.md` #10 |
| **Web cache deception** | edge caches by URL suffix, origin normalizes the suffix away → an authenticated page is stored under a public key and served to a cookie-less request | cache-deception |
| **Cache key confusion** | no URL crafting at all: the key is path+object-id and omits the authenticated identity, so the owner's entry is served to a different logged-in tenant. Oracle is the 404 → owner 200 → 404 state machine | cache-deception §key confusion |

**Cache-deception trigger:** any authenticated page whose response carries `cf-cache-status`,
`x-cache`, `x-served-by`, `age`, `x-vercel-cache`, or `x-amz-cf-id`, and does **not** carry
`Vary: Cookie`. That combination is the whole precondition — open
`references/cache-deception.md` and run the payload family. It is not a tenant-id swap, but it
crosses the same boundary (one customer's authenticated data reaching another requester), and it
is the one vector here that needs no second account.

## Algorithm

1. **Map** where the tenant id lives (table above) for every endpoint; infer the detail
   endpoint behind every org-scoped list. Worklist: endpoint → tenant-id location → object → sensitivity.
2. **Decode the JWT** you were issued. If `scope` contains `aws.cognito.signin.user.admin`
   *and* the backend authorizes tenancy from a custom claim (`custom:aId`/`custom:domain`),
   go straight to `references/cognito-takeover.md` — that is the P1/Critical path.
3. **Get B's tenant id** (a real foreign org id you're entitled to reference, or your own
   second org). If you need a victim org id and don't have one, harvest it from a leak
   oracle (`references/oracles-and-leaks.md`) — avatar CDN path, a member's JWT, a presigned
   storage-key prefix, a public team/directory endpoint — never guess strangers'.
4. **Swap the tenant id** into A's request (header/body/claim/path), everything else identical.
5. **Confirm via the ROUTING ORACLE** below (body content, not status — and 404≠403 here).
6. **Negative control (MANDATORY)**: prove A's tenant has NO legitimate access to B's org
   via the intended flow, AND find an **enforcing sibling** endpoint (same API family) that
   *correctly* returns a 403 not-authorized / entitlement-denied (or scopes empty) for a foreign org.
   "Sibling X enforces, vulnerable Y does not" is the single strongest convert argument (e.g. an
   entitlement-gated sibling route returns 403 while the vulnerable per-object route does not).
7. **Escalate reach** → write the lead to `targets/<program>/leads/` in the format in
   `../_shared/references/output-contract.md` → STOP.
8. **Before leaving the surface, read the cache headers on one authenticated page.** If an edge
   header is present and `Vary: Cookie` is not, run `references/cache-deception.md` — it reaches
   the same cross-customer read with a single account and is easy to walk past.

## Routing oracle — 404 does NOT mean authz here

The #1 tenant-boundary mistake is treating a wrong-tenant 404 as "authz working." In a
routing-key design a 404 is a **routing miss** (the id is a lookup key, not an access check),
and a *valid* foreign id returns 200 with data. Compare bodies, and test a garbage id.

| A-session + B's tenant id | Verdict |
|---|---|
| **200 with B's org data** (B's users/objects, distinct from A's) | **CONFIRMED cross-tenant read** |
| 200 but A's own / empty / generic body | not it — inspect body |
| **wrong/nonexistent org id → 404**, but **valid foreign org id → 200** | **routing miss** = the id is a lookup key, not an authz check → CONFIRMED, keep pushing |
| **403 not-authorized / entitlement-denied, or scoped-empty** on the *same* call | authz enforced on THIS route — but check if a sibling route lacks it |
| **garbage tenant id** (e.g. an all-zero uuid) accepted → data/compute | **no membership validation at all** — strongest signal; drives the entitlement variant |
| no-token → 401/403, presence-only `x-api-key` accepted | authn/key enforced but **tenant authz missing** → the swap is the bug |
| **empty tenant id → 400 "missing required field"** | field is read but never cross-checked to the token → strong signal, supply a foreign one |

## Severity / reach — how far to push

| Reach demonstrated | Severity |
|---|---|
| One foreign-tenant record you don't own | **High** when it carries tenant-scoped business data or PII; **Medium** when non-sensitive metadata only |
| Cross-tenant **mass PII** (org user list, 5–10 distinct, bounded) | High / Critical |
| Cost/entitlement action **billed to victim tenant** (paid LLM inference, quota) | **High** — a documented entitlement gate plus quantifiable billed compute; it scores at or above the bare cross-tenant read |
| Cross-tenant **write** (plant/modify an object in another org) | High / Critical |
| Cognito forged-claim → full victim-org data/admin | **Critical (P1)** |

**Reality check (the table and this paragraph must agree):**

- Cross-tenant read via tenant-header routing — Converts: **High** when the foreign-tenant
  response carries tenant-scoped business data or PII; **Medium** when it is non-sensitive
  metadata only; **Critical** when it reaches mass PII (an org user list, or 5–10 distinct
  bounded records).
- Entitlement / cost amplification — Converts: **High** — a documented entitlement gate
  plus quantifiable billed compute; it scores at or above the bare cross-tenant read.

Chase the chain that has a $ or PII consequence, and put the reach in the evidence so the
grade is earned from proof rather than potential.

## Safety & operational discipline (recalibrated to the safe-ladder — REACH impact)

- **Reads across your two tenants are the proof — do them.** Reading B's org data with A's
  session *is* the finding; do not stop one rung short "to stay safe"
  (`../_shared/references/safe-ladder.md`). A leaked org id / accepted swap / 200-on-write
  is rung 0 — climb to the cross-tenant read.
- **Cognito attribute write is on YOUR OWN user** — `UpdateUserAttributes custom:aId` mutates
  *your* Cognito account, not the victim's. The write itself is **rung 2** (own context);
  the VALUE decides the rung of the proof (see the rung block in
  `references/cognito-takeover.md`). **Revert the original `custom:aId` immediately** after
  the cross-tenant read.
- **The write is never the finding — the read is.** Only ever mutate objects/attributes you
  own; never write, delete, or corrupt another tenant's data. A cross-tenant *write* is proven
  by planting a sentinel in your OWN second org, or stated by inference — never by mutating a
  real foreign object.
- **RoE / UAT:** if the program restricts cross-tenant/privacy testing to `*-uat`/`*-oat`,
  do the full cross-tenant read there; on prod stop at a non-PII proof that the primitive
  exists and state the prod-equivalent impact by inference
  (`../_shared/references/safe-ladder.md` rung 4). Staging/UAT hosts (`api-qa.*`, `*-uat`,
  `*-oat`) are the right place for the full Cognito cross-tenant read.
- **Scope is a safety boundary, not a hunting filter.** Dial only hosts the program authorized; a victim id, a foreign org id, or an internal host inside the path/query/body/header is always allowed — only the connection target is gated. If a host is genuinely out of scope, pivot surface.
- **No DoS.** Bounded, paced sweeps (5–10 ids) to prove scale; if rate-limited, stop.
- **Redact** foreign-tenant PII in what you write down; keep ids in `id=<n>` / `id=<uuid>`
  form so reproduction and dedup survive.
- **Nothing blocks a step for you — decide the rung before the request is built.** When it
  would be other-tenant PII at scale or a write, drop to the non-PII prod read or the full UAT
  proof yourself (`../_shared/references/safe-ladder.md`); that is never a verdict of "no bug".

## Evidence checklist

`validation` re-proves; thin evidence is rejected. Capture a copy-pasteable set:

1. **Baseline** — the A-authorized request (A's session/tenant) + a snippet of A's own data.
2. **The swap** — the identical request with **B's tenant id** in the header/body/claim/path.
3. **Redacted foreign-tenant proof** — enough distinct fields to prove it is **B's org, not
   A's**, without dumping B's PII.
4. **The routing oracle** — garbage/nonexistent id → 404/400 while a valid foreign id → 200
   with data (`references/oracles-and-leaks.md`). That differential is what proves a missing
   check rather than shared data.
5. **Enforcing sibling** (strongest convincer) — "sibling X returns 403 not-authorized /
   entitlement-denied for a foreign org; vulnerable Y returns 200" — with request and response.
6. **Negative control** — A's tenant has no legitimate access to B's org via the intended flow.
7. **For Cognito** — the decoded JWT scope, the `UpdateUserAttributes` 200, the **re-auth JWT
   carrying the forged claim**, AND the cross-tenant read (the write alone is N/A), plus the
   note that you reverted the attribute.
8. **For entitlement/cost** — show the token is genuinely un-entitled (a consumer account-type
   claim, a null/absent owner-org claim) and that the foreign/all-zeros org id drove billed
   compute. Anchor severity on the vendor's published price, not the request count.
9. Keep ids in `id=<n>` / `id=<uuid>` form. Keep the lead claim string stable across sessions —
   the dedup key is `primitive|host|claim`.

## Handoffs (name them in the lead so the chain is reproducible)

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- Cognito `aws.cognito.signin.user.admin` scope / `UpdateUserAttributes` writability →
  **cloud-exploitation** (`../cloud-exploitation/references/cognito.md` §5c owns the AWS
  `X-Amz-Target` API detail; this skill owns the tenant chain).
- Internal `*.execute-api` gateway / datastore proxy → **cloud-exploitation**
  (`../cloud-exploitation/references/dynamodb.md`). The dual-authorizer *method* is owned
  by **broken-access-control** (`../broken-access-control/references/role-matrix.md` §2).
- A single object you own vs another user's — not an org boundary — is `idor-bola`'s
  object-id ladder (`../idor-bola/references/vectors.md`).
- A role/admin/gateway/plan gate rather than a tenant gate is `broken-access-control`
  (`../broken-access-control/references/role-matrix.md`).
- Tenant read leaks a key/token/presigned URL → **exposed-secrets**.
- About to claim Critical/High or a Cognito P1 → **validation** re-proves first, then
  **report-writing**.
- Client bundle mining needed to find the tenant header / internal gateway / org-id leak →
  **js-source-to-sink**.

## Dedup — reuse the technique, not a closed report

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

Also check this session's `targets/<program>/findings/`.
If the exact tenant boundary + endpoint on this target is already reported, it is
**CLOSED** — rotate to the next vector (header-routing → entitlement → Cognito →
dual-authorizer → guest→admin → body-spoof) and find the next distinct break. The
*tenant-isolation technique* is reusable across targets; a *specific submitted
finding* is not re-reportable.

## False-positive gate

NOT findings — don't report, don't burn turns: a clean 403 (not-authorized / entitlement-denied) on the
foreign org id where **no** sibling route lacks the check (authz enforced); own-tenant access
in a multi-tenant app (expected); a write-200 with no proven cross-tenant read behind it;
public org metadata already exposed by design; a wrong-tenant 404 that ALSO 404s on a valid
foreign id (real not-found, not a routing miss). **Hard gate:** no confirmed read of another
tenant's object you don't own (or one cost/entitlement action billed to a foreign org) +
proof A's tenant lacks legitimate access = not a finding.
