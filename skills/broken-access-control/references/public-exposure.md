# Public Exposure & Capability-URL Checks

Use when private data, metadata, files, dashboards, or SaaS resources may be
reachable without the expected authenticated role. Covers public/private mismatches,
pre-signed URLs, privacy-toggle bypass via API, exposed admin/KVM panels, and SaaS
portal over-exposure. Safe ladder: the **Rung mapping** above.

## Method

1. Identify the intended boundary (private report, protected file, hidden
   likes/history, restricted portal object, pre-signed URL, authenticated panel).
2. Baseline as an allowed actor, then **negative control** as anonymous / low /
   removed actor.
3. Test the alternate interface (mobile/API/GraphQL) once.
4. Capture MINIMAL proof: title, object type, redacted field names, status, headers,
   panel version — never bulk contents.
5. For an exposed admin/KVM/workstation panel: **passive GET/screenshot only** — do
   not click, type, open files, move the pointer, or change state.

## Pre-signed / capability URL scope failure

A file is delegated to a pre-signed URL (`X-Amz-Signature`, `Signature`, `token`)
that is not bound to user/object/path/method/expiry.

```bash
# does the signed URL leak in a response you can read cross-tenant?
curl -s "https://<service-host>/<per-object-route>" \
  -H "<tenant-header>:<VICTIM_ORG>"               # -> presigned S3 URL in body
# then GET the presigned URL from a DIFFERENT (or no) session:
curl -s "<PRESIGNED_S3_URL>"                       # oracle: file returns for a non-owner
# also mutate the path/id in the signed URL and replay; try after expiry
```

Oracle: the signed URL returns the object from a session that never owned it, or a
path/id mutation still validates, or it works past its stated expiry. A structured
storage-key shape like `{orgId}/{userId}/{resource}` both confirms cross-tenant reach
and enables path prediction.

## Privacy-toggle bypass via API (two owned accounts)

```bash
# set "hide my likes/activity" on account A, then read A from B or anon via the API
curl -s "https://$HOST/api/users/<A_ID>/likes" -H "$B_AUTH"        # or /graphql, or mobile route
```

Oracle: the setting says hidden/private, the UI honors it, but the GraphQL/mobile/API
route still returns the relationship. Prove on two accounts you own.

## Private metadata / SaaS portal over-exposure

- private report/program title, policy, updates, comments, like list, or attachment
  metadata reachable through an API/JSON route or a pending-collaboration state while
  the web UI hides it;
- Salesforce/community/helpdesk/recruiting portal where broad profile/object
  permissions let anonymous or low users query records/files/PII (list/search views
  leak more than individual pages). Request ONE known synthetic/public-safe record;
  otherwise capture field names/counts and stop. On bulk PII → hand to `validation`.

## Exposed admin/KVM/workstation panel

Internet-facing admin/KVM/router/camera/CI/DB/support panel with no auth. Passive GET
/ screenshot only; record host, product, title, auth absence, one non-sensitive
environment indicator. Confirm the host is an authorized program asset first — check it
against the scope in `targets/<program>/CLAUDE.md`. Do not interact.

## Good evidence

- unauthenticated/low request returns private metadata/content;
- privacy setting says private but the API returns the data;
- a sibling route or the UI denies while the alternate route succeeds;
- a pre-signed URL is reusable outside the intended actor/object/expiry;
- an exposed panel is reachable without auth (passive proof only).

## False-positive gates

- data is intentionally public;
- the capability URL is tightly scoped, expiring, unguessable, and delivered only to
  authorized users;
- the response is a generic public shell with no private metadata;
- browser cache / local app state caused the apparent access;
- proof requires interacting with a third-party console.

## Stop conditions (safe ladder)

- an exposed panel offers keyboard/mouse/power/session control;
- a file contains real third-party secrets/PII after minimal proof;
- a portal exposes bulk records — capture one, infer scale, hand to `validation`.
