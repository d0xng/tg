# Lifecycle & Persistence — access that outlives removal

Use when access SHOULD end after removal, deactivation, deletion, ban, suspension,
downgrade, token revocation, or account closure — but the old credential still
works. Safe ladder: the **Rung mapping** above.

**Split with `../../auth-flow-bypass/references/session-lifecycle.md`.** The question that routes it: *what was
supposed to end?*

- An **entitlement** ended (the seat, the role, the org membership, the grant, the
  plan) and access remains → **this file**.
- The **identity is unchanged** and a **session** should have died (logout, password
  change, 2FA reset, step-up, fixation, refresh-token revoke) →
  the `auth-flow-bypass` skill owns it.

They meet at revoke-vs-use TOCTOU, where the mechanism is a race — that lives in
`race-conditions.md`.

## Method

1. Establish access with an operator-controlled account and mint every credential
   type it can: web session, API token/PAT, mobile session, websocket, OAuth grant,
   integration token.
2. Capture a known-good request for each surface (save the exact curl).
3. Remove / downgrade / revoke the account (in an org you own).
4. **Immediately replay the saved requests** — timestamp before and after.

```bash
# saved before removal
curl -s "https://$HOST/api/v1/projects" -H "Authorization: Bearer $PAT" -D- -o/dev/null
# ... perform removal/downgrade/revocation in the owned org ...
date -u; curl -s "https://$HOST/api/v1/projects" -H "Authorization: Bearer $PAT" \
  | jq '{still_authorized:(.data!=null), count:(.data|length)}'
# also replay: mobile idtoken, websocket upgrade, GraphQL, export/download, a write
```

Oracle: the pre-removal token/session returns 200 + data (or performs a write) AFTER
the removal timestamp, while the canonical web route denies.

If the old credential only works for a short window after removal (a cached authz
decision, a propagation delay), the mechanism is revoke-vs-use TOCTOU: fire the
saved request concurrently with the revocation using `race-conditions.md`.

## High-value patterns

- banned/deleted user's API key still reads/writes;
- removed member keeps a mobile token or websocket;
- read-only downgrade does not invalidate an existing PAT/OAuth grant;
- revoked token still deletes/reads/updates;
- an old web session can still change password/email/role/settings;
- deprovisioned SCIM/SSO account stays linked locally and usable;
- removed collaborator still views comments/files/attachments;
- disabled account still uses GraphQL / an API-only route.

## Mobile cred chain persistence

Mobile apps often mint long-lived tokens through a side channel (Firebase Remote
Config → base64 service secrets → Azure/Auth0 `client_credentials` service token, or
a forged `alg:none` idtoken — see `invitation-identity.md` §A1). Those service/
forged tokens frequently survive user-level removal because they are not tied to the
user session at all. Replay them post-removal; if a broad service role (e.g. an
all-access scope) is still granted, the removal never reached that layer. Firebase/
Azure mechanics: hand to `cloud-exploitation` / `exposed-secrets`.

## Good evidence

- pre-removal token/session works after removal (timestamped);
- a server-side write or sensitive read succeeds post-removal;
- the canonical web route denies while the API/mobile/websocket route allows.

## Stop conditions (safe ladder)

- the action would delete/disable third-party data;
- proof requires removing a real user outside an operator-owned org;
- cleanup cannot safely restore the test account/org. Do writes only on your own
  synthetic records and revert.
