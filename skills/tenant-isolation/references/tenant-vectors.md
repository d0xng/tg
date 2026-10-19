# Tenant vectors — recognition, oracle, and attack by technique

Each vector below is a **methodology card**, not a fixed request: what the flaw IS, how to
recognize the endpoint TYPE on any target, the ORACLE ladder that confirms the swap crossed the
boundary, and how far it converts. Locate the target's own endpoint of that type, swap the tenant
identifier, and prove the **cross-tenant READ** (a write/200 is never the finding). Confirm with the
routing oracle in `oracles-and-leaks.md`, and always name the enforcing sibling.

## Contents

- §1 — Org/tenant header as a routing key → cross-tenant READ IDOR **(owned here)**
- §2 — Entitlement / cost-amplification variant, often scores above the read **(owned here)**
- §3 — Dual-authorizer gateway (Cognito JWT accepted where IAM is expected) — recognition only
- §4 — Guest / anonymous token → admin-namespace routes + WAF-origin bypass — recognition only
- §5 — Body-field identity spoof + tenant mass-assignment — recognition only
- §6 — Membership derived from an unverified email domain (auto-join)
- Vector-selection cheat-sheet

§3, §4 and §5 are recognition cards: the method is owned by `broken-access-control`
(`../../broken-access-control/references/role-matrix.md` §2 and §1,
`../../broken-access-control/references/graphql-api.md` §1). Recognize the shape here,
then open that skill and run it yourself.

---

## §1 — Org/tenant header as a routing key → cross-tenant READ IDOR

> **This section is the single owner of this vector for the pack.** `idor-bola`, `broken-access-control` and `auth-flow-bypass` keep recognition cards that route here.

**The flaw:** an endpoint carries the tenant identity in a **header/param** (a tenant/org/account
header used as a routing key) and the handler uses that value as a **lookup/routing key** to fetch
the object — it never verifies the caller is a member of that tenant. Authentication is enforced (a
Bearer, and often a presence-only api-key that is really a public client_id — resolve via
`../../_shared/references/public-by-default-keys.md`; the key is not the bug, the missing tenant
check is), but tenant AUTHORIZATION is missing on this route.

- **Recognize it:** a **per-object** read (status / detail / executions / export / download) that
  takes the tenant id from a header or param rather than deriving it from the session. The value may
  be a plain uuid or a **composite** (a uuid with an org/domain suffix) — treat every segment as
  attacker-controlled. The **list** sibling is usually scoped (empty for non-members) while the
  per-object route is not; that asymmetry is the tell.
- **Attack:** replay your own authenticated per-object request with the tenant header/param swapped
  to a foreign org id you may ethically reference (your own second org, or one harvested from a leak
  oracle — `oracles-and-leaks.md`). Everything else identical.
- **Oracle ladder:** list with a foreign org → scoped/empty (proves the list enforces = baseline);
  per-object with foreign org + its object id → full read = **the finding**; wrong/nonexistent org
  id → 404 = **routing miss, NOT authz** (it was looked up and missed, not rejected); garbage/all-zero
  org id accepted → data returned = **no membership validation at all**; empty tenant id → 400
  "missing field" = read but never cross-checked to the sub. Full differential in `oracles-and-leaks.md`.
- **Leak bonus:** these responses frequently return presigned storage URLs whose **key prefix embeds
  the tenant/user/resource ids** (`{orgId}/{userId}/{resourceId}/...`) — that layout is itself another
  victim-org-id oracle (feeds `oracles-and-leaks.md`) and often reveals the object id is a
  **templated / low-entropy** value (a fixed prefix + your-own-activity ids + a date window + a short
  random suffix), i.e. derivable rather than random. Decompose it (idor-bola ID-type playbook) before
  assuming it is unguessable.
- **Enforcing sibling (strongest convincer):** find a route in the same API family that DOES enforce
  the tenant check for a foreign org (returns a 403 not-authorized / entitlement-denied body, or
  scopes empty). "Sibling X enforces, vulnerable Y returns the foreign org's data" proves the check
  is *expected* and *missing here*, not that the API is intentionally open.
- **Converts:** **High** when the foreign-tenant response carries tenant-scoped business data
  or PII; **Medium** when it is non-sensitive metadata only; **Critical** when it reaches mass
  PII (an org user list, or 5–10 distinct bounded records). If the same missing check drives
  paid compute → **§2** (often scores higher). A single self-owned-object half → `idor-bola`
  (`../../idor-bola/references/vectors.md`).

---

## §2 — Entitlement / cost-amplification variant (often scores ABOVE the read)

> **This section is the single owner of this vector for the pack.** `idor-bola`, `broken-access-control` and `auth-flow-bypass` keep recognition cards that route here.

**The flaw:** the **same** missing membership check, on a route that runs **paid compute** (LLM
inference, background jobs, rendering, quota-metered work) keyed off the tenant/org header rather than
a checked entitlement — so a consumer-tier identity drives billable work charged to the victim/provider
org. This has a documented entitlement gate plus a dollar cost, so it typically triages *higher* than
the pure read.

- **Recognize it:** a POST/action route that executes paid/metered work and keys billing/quota off the
  org header (or a body org field). The header-routing IDOR in §1 and this variant are twins — whenever
  you find one, test the other.
- **Attack:** replay that route with your own **consumer-tier** Bearer and an obviously-invalid org id
  — a syntactically valid but unregistered value; an all-zeros uuid is the canonical probe. A 200 that
  returns the paid result = the org id is a routing/billing key with no membership or entitlement check,
  and the compute is billed to the org, not to you.
- **Convincer — prove your token is genuinely un-entitled:** decode your Bearer and show a
  free/consumer tier with **no paid org attached** (a consumer account-type claim, a null/absent
  owner-org claim). You own no entitled org yet you drive paid compute.
- **Enforcing sibling:** a neighboring paid route that correctly returns a 403 not-entitled for the
  **same** caller — proof the vulnerable route dropped the gate its neighbor keeps.
- **Why it converts higher:** cost amplification + a documented entitlement gate = quantifiable $
  impact, whereas the read alone is often "low-sensitivity metadata." When you find a header-routing
  IDOR, **always** check whether the same gap drives billable compute / quota — that is the escalation.
- **Bound the proof (`../../_shared/references/safe-ladder.md` rung 2b).** Read the balance/quota,
  invoke once, read it again, invoke again: the meter that did not move IS the proof. Two to three
  invocations, on your own free/consumer account. Never bulk-generate to "show scale" — anchor the
  severity on the vendor's published price for the plan you bypassed. Anything that would bill a
  **victim tenant** stops at ONE invocation, and only after the read-side proof exists.
- **Converts:** **High** — a documented entitlement gate plus quantifiable billed compute; it
  scores at or above the bare cross-tenant read.

---

## §3 — Dual-authorizer gateway (Cognito JWT accepted where IAM is expected)

**The flaw:** recon/JS reveals a **second/internal** API Gateway (a
`*.execute-api.<region>.amazonaws.com/<stage>` host distinct from the main API). Most routes expect
**IAM SigV4** and reject a plain token with the SigV4 error `"Credential should be scoped to a valid
region"`, but a **few routes were mistakenly left with a Cognito-JWT authorizer** — any user's
`id_token` is accepted — and the Lambda does **zero ownership validation** on the tenant/account/project
id in the path. A user-controlled **destination field** on a copy/export action lets you exfiltrate a
victim's object into your own account.

- **Recognize it:** two distinct `execute-api` hostnames in the JS (main vs internal); a route family
  under the internal gateway; per-route behavior that splits into **"accepts my JWT"** vs
  **"IAM/SigV4 error."** A read-only enumeration route (an "exists"/lookup that echoes a victim's
  account id from an email) is the finder — use it read-only for scope.
- **Attack, oracle and replay ladder:** owned by
  `../../broken-access-control/references/role-matrix.md` §2 (route bucketing JWT-accepting
  vs IAM-error, the caller-controlled destination field, the read-only enumeration route).
  Recognize the two `execute-api` hostnames here, then run `broken-access-control`.
- Converts: **High** when a JWT-accepting route lacks the ownership check AND a
  caller-controlled destination exposes another account's object; **Medium** if only the
  authorizer gap is proven.
- Internal gateway / IAM / datastore detail behind the route → `cloud-exploitation`.

---

## §4 — Guest / anonymous token → admin-namespace routes (missing role check) + WAF-origin bypass

**The flaw:** a guest/anonymous login returns a **usable** token (no credentials needed) and an
**admin route namespace** enforces **no role check** — any valid token, including the credential-free
guest, reads mass PII / procurement / file data via paginated GETs. This is broken function-level
(vertical) access control on a tenant/admin surface — mass PII = P1.

- **Recognize it:** an anon/guest login endpoint (sometimes gated only by a hardcoded key lifted from
  the JS) that mints a real token; an **admin-namespace route group** that exists **only in JS**, never
  in the UI (capture it from `js-source-to-sink`). The admin routes accept any valid session, not an admin role.
- **Attack:** owned by `../../broken-access-control/references/role-matrix.md` §1 (mint the guest token, map the admin-namespace route group, replay, and take the BOUNDED 5-10-record scale proof — never paginate the table). Converts: **Critical** when the admin group returns cross-user PII; **High** when it returns non-PII privileged data. The reachable route alone is not a finding.
- **WAF-origin bypass (when the edge blocks you):** owned by
  `../../broken-access-control/references/role-matrix.md` §1 — SPF/`dig TXT` origin
  recovery, the full origin-discovery ladder, and the `curl --resolve` dial. Apply it here
  and keep the guest→admin proof in this section.

---

## §5 — Body-field identity spoof + tenant mass-assignment (write-side; escalate to convert)

**The flaw:** the auth gateway validates the Bearer **signature**, but the handler trusts an
**identity field in the JSON body** (a field naming a user/owner — `user_id` / `userId` / `ownerGUID` /
`author`, or a per-message / per-conversation identity) and never compares it to the token `sub`. (A
public api-key, if present, is only presence-checked.)

- **Recognize it:** an authenticated write (POST/PUT/PATCH) whose body names a user/owner. Lives in
  feedback/rating, comments, profile & preferences, "report abuse", share/invite, on-behalf-of actions.
- **Attack + oracle ladder:** owned by `../../broken-access-control/references/graphql-api.md` §1.
- Converts: **Medium** (attribution / metric / RLHF poisoning). Raise it only by proving the read side or a downstream routing effect (moderation / Trust-&-Safety queue). The object half → `idor-bola`.
- **Tenant mass-assignment (same family):** on a create/update, set an `orgId` / `tenantId` /
  `accountId` body field to **plant** an object in another tenant. Prove it only on **your own second
  org** (rung 2) — a real foreign-tenant write is stated by inference, never executed. Owner of the
  general mass-assignment vector: `../../idor-bola/references/vectors.md` #4.

---

## §6 — Membership derived from an UNVERIFIED email domain

The tenant boundary is not a header here, it is `@company.com`. A platform onboards an
enterprise, registers its domains, and auto-provisions any account whose address ends in
one of them into that workspace — the "so new hires just log in" convenience. If the
address is never verified, **anyone who can create an account with that address is a
member of that organisation.**

**Recognize it:** a workspace/config response naming the domains it claims —
`"domains": ["acme.com","acme.io"]`, `invite_only: false`, `auto_join_domains`,
`allowed_email_domains`, `sso_domain` — or onboarding copy promising that colleagues on
the company domain join automatically. Any org-scoped read endpoint
(`/organizations/members`, `/workspaces`, `/teams`) is then the payload.

**The enabler is usually a public identity provider the app fronts.** The app's UI may
offer only "Sign in with Google/SSO", but the underlying identity service accepts a
direct registration call with the browser key that ships in the bundle. That key is
public by design and is **not** the finding — it is the legitimate input, and the finding
is the unverified-domain membership behind it:

```bash
# Firebase Identity Toolkit — the AIza browser key is enough to create an account
TOKEN=$(curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$AIZA" \
  -H 'Content-Type: application/json' \
  -d '{"email":"probe@'"$DOMAIN"'","password":"<random>","returnSecureToken":true}' \
  | jq -r .idToken)
# then present it as the app's own bearer
curl -s -H "Authorization: Bearer $TOKEN" "https://$API/platform/v2/organizations/flat-members?page_size=400"
```

`accounts:signUp` returning an `idToken` with no verification step is the whole enabler.
`EMAIL_EXISTS` back instead means the address is taken — which is itself an account-
existence oracle, so use a random local part. Cognito's equivalent is `SignUp` +
`UserConfirmed:true` (`../../auth-flow-bypass/references/cognito-auth.md` §D); Supabase's
is `/auth/v1/signup` with the anon key.

**Two traps that produce false negatives:**

- **provisioning is asynchronous.** The workspace assignment is triggered on account
  creation and lands a second or three later. Calling the org endpoint immediately
  returns `403`/empty, which reads as "enforced". Sleep, retry, and only then judge.
- **the token is not the app's own token.** The identity provider's `idToken` may need
  exchanging, or the app may want a client-type header (`<Vendor>-Client-Type: portal`,
  `X-App-Client`, `X-Client-Id`) copied from a normal browser request. Replay the
  bundle's own headers before concluding the token is rejected.

**Prove it on a domain you control first.** Register your own domain in a second
workspace where the platform allows it, or use the target's *own* domain only for the
minimum read that establishes membership. Then **count the records and stop** — one page
of the member list with `total_count` is the proof; do not paginate the directory.

**Converts: High**, and **Critical at mass PII** — a full employee directory with names,
corporate emails, last-login timestamps, roles and linked SCM accounts is exactly the
"how many records" question the severity ladder turns on, so lead with the count. The
same response commonly carries internal API hostnames and SCM org identifiers; hand
those to `../../exposed-secrets` and `../../ffuf-web-fuzzing` rather than padding the
severity with them.

**Corpus case:** `3631100` — `h1/reports/3631100-qodo-duplicate.md` (medium · duplicate;
311 + 66 members across two claimed domains, two HTTP requests, no authentication).

---

## Vector-selection cheat-sheet

- JWT has `scope: aws.cognito.signin.user.admin` + tenancy comes from a custom attribute →
  **`cognito-takeover.md`** (Critical path, do this first).
- A tenant header/param routes per-object reads → **§1**; then check if it drives paid compute → **§2**.
- JS shows a second `*.execute-api/<stage>` gateway → **§3** (bucket routes JWT-accepting vs IAM-error).
- Guest/anon login + an admin-namespace route group → **§4** (+ SPF-origin bypass if WAF-fronted).
- Identity field in the request body → **§5** (write-side; find the read to convert).
- An authenticated page answers with an edge cache header (`cf-cache-status`, `x-cache`, `age`,
  `x-vercel-cache`) and no `Vary: Cookie` → **`cache-deception.md`** (no tenant id to swap and no
  second account needed — the cache does the crossing).
