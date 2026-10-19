# Identity Proof — claim forgery, invites, verification, recovery, SSO/SCIM

<!-- workspace rung mapping -->

> **Rung mapping.** This file was written against a five-rung safety ladder. In this workspace those rungs are: **1** read-only · **2** write to an object _you_ own, reverted immediately · **3** bounded scale proof, 5–10 records, never a dump · **4** the same proof relocated to a UAT/OAT host · **5** anything touching a third party's object — **pause and ask d0x directly before executing**, providing the exact request, affected state and rollback plan. This is interactive routing, not a terminal state.

## Contents

- Core principle
- A. Identity-claim forgery (JWT / Cognito)
  - A1. JWT alg:none / RS256→HS256 / claim-vs-path ladder
  - A2. Cognito self-writable custom attribute → forged tenant claim
- B. Invitations, verification, recovery, SSO/SCIM
  - Method
  - High-value patterns
  - Good evidence
  - Stop conditions (safe ladder)

Use for anything where the system must prove control of an identity — a mailbox, domain, IdP identity, tenant, or signed claim — before granting access or a role. Safe ladder: the **Rung mapping** above.

## Core principle

**Typed identity is not proof.** A profile email, a body `user_id`, a JWT claim, or a Cognito custom attribute is only as trustworthy as the check behind it. The finding is the moment the server trusts a value the caller controls instead of proving it.

---

## A. Identity-claim forgery (JWT / Cognito)

### A1. JWT alg:none / RS256→HS256 / claim-vs-path ladder

> **Owner:** token forgery itself — `alg:none`, RS256→HS256, `kid`/`jku`/`x5u` — is owned by the `auth-flow-bypass` skill. This card keeps the recognition signal, the oracle, and the _authorization_ consequence: which identity the server trusts once a tampered token is accepted.

Run in order; stop at the first that the server accepts.

1. **alg:none + empty signature** — re-encode the header `{"alg":"none"}`, keep or modify the claims (`sub`, `user_id`, `role`, a tenancy claim), drop the signature. If accepted, forge any identity. Class: CVE-2018-1000531 (inversoft prime-jwt), CVE-2020-28042 (ServiceStack before 5.9.2, empty signature). Recurrent mobile chain: an id-token with `{"alg":"none"}` + empty sig accepted by the API, then a secondary signed header (an HMAC recomputed with a key hardcoded in the decompiled app) satisfied from that key.
2. **RS256→HS256 confusion** — take the RS256 public key (from `/jwks.json`, `/.well-known/openid-configuration`, or a leaked cert), re-sign the token HS256 using that public key bytes as the HMAC secret. If the verifier picks the alg from the header, it validates. Class: CVE-2015-9235 (node `jsonwebtoken` before 4.2.2), CVE-2016-10555 (`jwt-simple` <= 0.3.0), CVE-2016-5431 (PHP JOSE by Gree before 2.2.1).
3. **claim-vs-path mismatch** — submit a token whose `sub`/`user_id`/`org` claim disagrees with the path/body id; observe which one the server trusts for authorization. If it trusts the path/body, that is the BAC.
4. **`kid` / `jku` / `x5u` injection** — `kid` path traversal to a predictable file, or point `jku`/`x5u` at an attacker-hosted JWK set. If honored, sign with your key.

Oracle: a tampered/forged token returns another user's data or performs their action; the server never rejects the broken signature.

### A2. Cognito self-writable custom attribute → forged tenant claim

When the JWT _access_ token carries `scope: aws.cognito.signin.user.admin`, the user can call the Cognito Identity Provider API directly. If the pool did not mark a tenancy-bearing custom attribute (`custom:<tenantAttr>` — a tenant/account id, `custom:domain`, `org`, an `is<vendor>Customer` flag) admin-write-only, overwrite it to another tenant's id, re-authenticate, and read across the tenant boundary. The AWS API calls are identical for every Cognito app — only the attribute name and the tenant-scoped read route are target-specific. Write **your own second org's** uuid by default; see the rung block below for when a real victim org uuid is allowed.

> **Owner:** the AWS API sequence is the `cloud-exploitation` skill §5c; the tenant chain and the read that proves it is the `tenant-isolation` skill. This card keeps recognition, oracle, and verdict only.

The victim tenant id typically leaks via avatar/CDN asset paths keyed by tenant id, other users' JWTs, same-domain auto-assignment, and public teams/members routes. Pool id + client id come from the JWT `iss`/`client_id`.

Oracle: `UpdateUserAttributes` → 200 on an authz-bearing attribute (pool never marked it admin-write-only); the re-minted JWT carries your forged value; the tenant-scoped endpoint returns another tenant's PII.

**Rungs for this chain (identical in every copy):**

1. `GetUser` on your own access token — **rung 1** (read-only).
2. `UpdateUserAttributes` on your own Cognito profile — **rung 2**. The write mutates _your_ account, never the victim's; revert it the moment the read is demonstrated.
3. The VALUE you write decides the rung of the _proof_, not of the write:
   - **a second org YOU own → rung 2. This is the default and the preferred proof.** Seed one (self-signup; `UserConfirmed:true` lowers the bar) before reaching for a real org id.
   - **a real victim org UUID on a UAT/OAT host (`*-uat`, `*-oat`, `api-qa.*`) → rung 4.** Use this when the app will not let you create a second org.
   - **a real victim org UUID on prod → rung 5: ask d0x directly before executing**, bring the exact request, read ONE record, revert immediately. Prefer stating prod impact by inference from the rung-2/rung-4 proof so this rung is never needed.
4. `UpdateUserAttributes → 200 {}` is **N/A on its own** — the finding is the end-to-end cross-tenant READ after re-auth.

Converts: **Critical (P1)**. The `UpdateUserAttributes` 200 alone is N/A.

Deep Cognito mechanics (pool/client enumeration, identity-pool creds): the `cloud-exploitation` skill. This is a tenant-isolation bypass — the tenant chain is owned by the `tenant-isolation` skill.

---

## B. Invitations, verification, recovery, SSO/SCIM

Use two operator-controlled inboxes/domains/accounts only.

### Method

1. Create invite / recovery / linking flows between accounts A and B you own.
2. Test whether acceptance depends on the unique link/token or merely on an email _value_ matching the account profile.
3. Vary: unverified email, changed email, secondary email, expired/resent invite, different session, different browser, mobile/API acceptance, role-upgrade acceptance.
4. For SSO/SCIM, test deprovision/reprovision and identity mismatch in a controlled IdP tenant only.

### High-value patterns

- unverified email accepts an invite;
- low member reads pending owner/admin invite emails, then registers/links one and accepts an elevated role;
- invite token not bound to recipient/org/role/current-email;
- password reset delivered to or revealed for an unverified/secondary email;
- SCIM creates/links to an existing account without strong identity binding;
- account linking trusts email equality without IdP proof;
- the role in an invite can be upgraded by tampering the request body.

### Good evidence

- an account with no mailbox proof joins an org / gains a role;
- invite/recovery works from the wrong session/account;
- pending-invite data leaks enough identity to target escalation;
- negative control shows the normal flow requires email/link/IdP proof.

### Stop conditions (safe ladder)

- a real third-party invite or inbox would be affected;
- proof requires guessing employee emails at scale;
- a sensitive reset/invite link would be sent to a non-owned mailbox. For the final ATO step (password/2FA change on prod), ask d0x directly before executing, then revert.
