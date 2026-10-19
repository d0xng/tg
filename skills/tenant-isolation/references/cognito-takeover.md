# Cognito self-writable custom-attribute → cross-tenant takeover (Critical / P1)

The highest-impact tenant-isolation chain — typically Critical / P1. When a multi-tenant app
authorizes tenancy from a Cognito **custom attribute** the user can rewrite themselves, you
overwrite it to another org's id, re-authenticate to mint a JWT carrying the **forged tenant
claim**, and read that org's data end to end.

> **Division of labour:** this file owns the **tenant chain** (why it works, what to read, what
> proves the finding). `../../cloud-exploitation/references/cognito.md` §5c owns the **AWS
> Cognito API mechanics** (the exact `X-Amz-Target` request bodies, pool/client recovery, the
> re-auth call, the revert). When you confirm the linchpin below, open `cloud-exploitation`
> yourself, run the AWS calls there, and come back here to drive the cross-tenant read.

## Contents

- Linchpin (both must hold)
- The chain (end to end)
- The one rule for THIS chain
- Getting the victim org UUID (it is NOT secret)
- Replay ladder
- Safety (recalibrated — reach the read, own-account write)

## Linchpin (both must hold)

1. Your **access token** carries `scope: "aws.cognito.signin.user.admin"`. This scope authorizes
   the user to call `GetUser` / `UpdateUserAttributes` **against their own account** directly on
   `cognito-idp.<region>.amazonaws.com` with just the access token — no admin creds.
2. The backend derives tenancy from a **custom attribute** claim: `custom:aId`, `custom:domain`,
   `custom:tenantId`, `custom:org`, etc. — and the user-pool did **not** mark that
   attribute admin-write-only (mutable, self-writable).

Recover the pool id and client id from the JWT itself: `iss` = `https://cognito-idp.<region>.amazonaws.com/<POOL_ID>`, and the `client_id` claim = the app client id.

## The chain (end to end)

```
decode JWT  → confirm scope + pool/client + which custom attr carries tenancy
GetUser     → list your current custom attributes (see custom:aId = <your-org-uuid>)
UpdateUserAttributes  custom:aId = <YOUR-SECOND-ORG-UUID>  → 200 {}   ← NOT the finding yet
                       (<VICTIM-ORG-UUID> only on UAT/OAT (rung 4), or on prod it requires d0x's approval before execution (rung 5))
re-authenticate (app signin, or a raw InitiateAuth call)  → NEW JWT carries forged custom:aId, sub unchanged
GET tenant-scoped data endpoint  → returns the VICTIM org's data     ← THE FINDING
restore custom:aId = <your-org-uuid>  (REVERT immediately)
```

**AWS API calls: owned by `../../cloud-exploitation/references/cognito.md` §5c** — the exact
`X-Amz-Target` bodies for `GetUser` / `UpdateUserAttributes` / `InitiateAuth`, pool+client
recovery from the JWT, and the revert. Run them there; drive the tenant chain from here.

**Read (the finding):** with the re-issued token (carrying the forged tenant claim), call any
**tenant-scoped data endpoint** — the one whose response the backend keys off the tenant claim you
overwrote. The org's user list is the highest-value target (mass PII); it returns the **victim org's**
data, not yours. If it returns your own org's data, the backend re-resolved tenancy from `sub` and
there is no finding.

## The one rule for THIS chain

**`UpdateUserAttributes → 200 {}` is N/A on its own.** A 200 only proves the attribute is
writable — the backend may re-resolve tenancy from `sub` on the next read and ignore the forged
claim. **You must prove the cross-tenant READ after re-auth.** If the read returns your own org's
data, the backend re-validates and there is no finding; if it returns the victim org's data, it's
the Critical. Always demonstrate the read E2E.

## Getting the victim org UUID (it is NOT secret)

You need a real foreign `aId`/`domain` to write. It leaks constantly — see
`oracles-and-leaks.md`; the ones most common for this Cognito-attribute pattern:
- **avatar CDN path:** `/assets/accounts/{aId}/...` (the org UUID is in the image URL).
- **any member's JWT** (`custom:aId` claim is visible on decode).
- **same-domain auto-assign:** signing up with a corporate email may auto-join / reveal the org.
- **a public team / directory endpoint** that echoes the org id.
- **a presigned storage-key prefix** (`{orgId}/...`) from other services in the same tenant.

## Replay ladder

1. Decode the JWT — confirm `aws.cognito.signin.user.admin` + extract pool/client from `iss`/`client_id`.
2. `GetUser` → list your custom attributes; identify which one the backend trusts for tenancy.
3. `UpdateUserAttributes` → overwrite the tenant attr with **your own second org's UUID** by
   default → expect `200 {}`. A real victim org UUID belongs on UAT/OAT, or on prod only after
   d0x's approval before execution — see the rung block below.
4. Re-authenticate (a raw `InitiateAuth` call needs no extra tooling — the request body is in
   `../../cloud-exploitation/references/cognito.md` §5c) → decode the new JWT → confirm the
   forged claim is present and `sub` unchanged.
5. Hit a tenant-scoped data endpoint → **confirm it returns the OTHER org's data** (the finding).
6. **REVERT** `custom:aId` to your original value immediately.

## Safety (recalibrated — reach the read, own-account write)

**Rungs for this chain (identical in every copy):**
1. `GetUser` on your own access token — **rung 1** (read-only).
2. `UpdateUserAttributes` on your own Cognito profile — **rung 2**. The write mutates *your* account, never the victim's; revert it the moment the read is demonstrated.
3. The VALUE you write decides the rung of the *proof*, not of the write:
   - **a second org YOU own → rung 2. This is the default and the preferred proof.** Seed one (self-signup; `UserConfirmed:true` lowers the bar) before reaching for a real org id.
   - **a real victim org UUID on a UAT/OAT host (`*-uat`, `*-oat`, `api-qa.*`) → rung 4.** Use this when the app will not let you create a second org.
   - **a real victim org UUID on prod → rung 5 — not attempted**: ask d0x directly with the exact request before executing. Prefer stating prod impact by inference from the rung-2/rung-4 proof so this rung is never needed.
4. `UpdateUserAttributes → 200 {}` is **N/A on its own** — the finding is the end-to-end cross-tenant READ after re-auth.

Converts: **Critical (P1)**. The `UpdateUserAttributes` 200 alone is N/A.

- **Revert the attribute** the moment the read is demonstrated — leaving your `aId` pointed at a
  foreign org would break your own account's scoping.
- Read **one** victim-org object (the user-list count / a couple of records) to prove mass PII —
  do not dump the whole org (`../../_shared/references/safe-ladder.md` rung 3).
- Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle. Apply the methodology to **any** Cognito multi-tenant app where an authz-bearing custom attribute is self-writable.
