# Oracles, convincers, and victim-org-id leak sources

Two things separate a real tenant-isolation finding from noise: the **oracle** (does the swap
actually cross the boundary, or is authz enforced?) and the **victim org id** (which you need to
demonstrate the read without guessing strangers' data). Both are here.

---

## The 404-routing-miss vs 403-authz oracle

In a routing-key design the tenant id is a **lookup key**, not an access check — so a wrong id
returns **404 (routing miss)** and a *valid foreign* id returns **200 with data**. Do not mistake
the 404 for "authz working." Run the differential:

| Test | Result that means "routing key, no authz" | Result that means "authz enforced" |
|---|---|---|
| valid foreign org id | **200 with the foreign org's data** | 403 not-authorized / entitlement-denied, or scoped-empty |
| nonexistent/garbage org id | 404 "not found" (it *looked it up* and missed) | 403 (rejected before lookup) |
| all-zero id (an all-zero uuid, in the field's own format) | **accepted → data/compute** = zero validation | 403/400 rejected |
| empty id | `400 "missing required field"` (read but not cross-checked) | 401/403 |
| your own org id | 200 with your data (baseline) | 200 with your data (baseline) |

**Confirm rule:** valid-foreign → 200-with-their-data while garbage → 404 is the signature of a
missing membership check. If BOTH valid-foreign and garbage return 404, it's a genuine not-found
(the id may be scoped) — not a routing-miss finding.

## The garbage-tenant-id test (fastest disproof-of-authz)

Send a syntactically valid but obviously-fake tenant id in whatever format the field uses, and see if
it's honored:
- Plain uuid form: an all-zero uuid `00000000-0000-0000-0000-000000000000`, `deadbeef-dead-beef-dead-beefdeadbeef`, or `11111111-1111-1111-1111-111111111111`.
- Composite form: if the field is a composite (a `uuid@org` / `id@domain` shape), keep the shape but plug a fake value into each segment.

If the server **accepts a garbage id** (returns data, drives compute, or 400-on-empty but
200-on-garbage), there is **no membership validation at all** — the strongest possible signal, and
the exact primitive behind the entitlement/cost-amplification variant (`tenant-vectors.md` §2).

## The enforcing-sibling convincer (the single strongest convert argument)

Triagers downgrade "the endpoint took my header" as speculative. The fix: find a **sibling
endpoint in the same API family that correctly enforces** the tenant check, and show the
vulnerable one does not. "Sibling X returns a 403 not-authorized / entitlement-denied for a foreign
org; vulnerable Y returns 200 with the foreign org's data" proves the check is *expected* and
*missing here*, not that the whole API is intentionally open.

- An entitlement-gated sibling in the same API family (a neighboring paid/compute route) returns
  **403 not-entitled** for a foreign org while the vulnerable per-object / action route reads or bills
  that foreign org — same identity, opposite result.
- Generic: the **list** endpoint scopes to your org (empty for a foreign org) while the **per-object**
  endpoint reads any org — the list enforcing proves the per-object route dropped the check.
- Always include the sibling request/response in the lead evidence.

## The negative control (mandatory before reporting)

Prove A's tenant has **no legitimate path** to B's org via the intended UI/API flow — otherwise the
resource may be shared/public and there is no bypass. Show: (1) A cannot see B's org in the normal
org switcher / list, (2) the direct swap returns B's data anyway. Without this `validation` rejects.

---

## Victim-org-id leak oracles (get a real foreign tenant id — never guess strangers')

To demonstrate a cross-tenant read you need a **real** foreign org id you can ethically reference.
Harvest it from these leak sources (the target's own surfaces), not by brute-forcing user data:

| Source | Where the org id appears |
|---|---|
| **Avatar / asset CDN paths** | `/assets/accounts/{aId}/...`, `/cdn/orgs/{orgId}/logo.png` — the org UUID is right in the image URL |
| **Members' JWTs** | decode any org member's token → `custom:aId` / `org` / `tid` claim is visible |
| **Presigned storage keys** | a storage-key prefix that embeds the org id (`{orgId}/{userId}/{resourceId}/...`) in run/export/download responses |
| **Public team/dir endpoints** | a public team / org / directory / search endpoint that echoes org ids for records you don't own |
| **Same-domain auto-assign** | signing up with a corporate email auto-joins or reveals the org id |
| **Invite / share links** | `?org=<uuid>`, `/invite/{orgId}/...` in emails and share URLs |
| **Error messages** | verbose 500s / validation errors echoing the org id you referenced |
| **List endpoints (paginated)** | an over-broad list leaking `{orgId}` for records you shouldn't see |
| **GraphQL introspection** | org node ids `base64("Org:<n>")`, or `organizations { id }` returning more than yours |

**Rule:** these ids are **not secret** — using a leaked/derived foreign org id to prove the missing
check is the finding. Reference your own second org where possible (rung 2); if a real foreign org
id is needed, take it from one of these target-provided oracles, read **one** object to prove the
class, and redact the foreign PII in what you emit (`../../_shared/references/safe-ladder.md` rung 3).
