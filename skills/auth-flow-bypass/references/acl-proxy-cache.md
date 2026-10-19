# Admin Login Bypass, Proxy / Cache ACL & WAF-Origin

Use for admin login bypass, cache-manager ACL bypass, reverse-proxy ACL
differentials, localhost/internal ACL checks, customer-lookup admin tools, and
unauthenticated management interfaces. The finding is **the data or action the
gate protects** — an admin route returning `200` with a *title* is rung 0. Read
one protected record (safe-ladder rung 1/3), then state scale by inference.
Guest/anon-token-to-an-admin-namespace and the `dig TXT` WAF-origin bypass are
owned by `../../broken-access-control/references/role-matrix.md` §1. This file
covers the ACL differentials that reach the same admin surface.

## Invariants

- admin/management endpoints require authentication and the correct role/source;
- proxy/cache ACLs protect manager/internal/local-only URLs regardless of path
  normalization, method, host header, absolute-form URI, trailing chars, or
  cache behavior;
- an internal customer-lookup tool never returns records without an admin session.

## A — Reach the admin surface (then READ, don't just fingerprint)

1. Identify the protected endpoint and its expected auth boundary.
2. Send one unauthenticated request. If it serves data, **read one record** — the
   customer row, the internal note, the config value. That read (PII redacted, id
   in `id=<n>` form) is the proof, not the HTTP status. Do NOT stop at "200 +
   `<title>Admin</title>`".
3. If it enforces, run the differential ladder (B) — one alternate form at a time.
4. Once you can read, state "N records / all customers exposed" by inference from
   the one row + a `count`/pagination header. Never paginate the whole table.

## B — Proxy / normalization / ACL-differential ladder

The front proxy allows/denies on the raw path; the origin normalizes differently.
Try each against the canonical-denied admin/manager route:

> **Owner:** the full 403-bypass ladder — every path transform, the method
> dimension, the framework override matrix and the oracle — lives in
> `../../broken-access-control/references/role-matrix.md` §1b. Do not replay it
> from here; open that file. This section keeps only the recognition signal:
> an edge that answers 403 on a path its origin plausibly still serves, with a
> proxy/cache layer in between.

Next.js middleware-auth bypass (`x-middleware-subrequest: middleware`,
CVE-2025-29927) and the full 403/path-normalization transform ladder live in the
path-normalization card of `../../broken-access-control/SKILL.md` — run them
against any edge-blocked admin route before concluding the gate holds.

Cache-manager / server-status style (`/server-status`, `/nginx_status`,
`/manager/html`, Squid cachemgr `cache_object://`, Varnish, Traefik/Consul/
Kubernetes dashboards): the ACL often keys on source IP or path — an absolute-URI
or `X-Forwarded-For: 127.0.0.1` frequently reaches it. Read one status/manager
page's data; do not invoke destructive manager actions (purge/restart/deploy).

## C — WAF-origin bypass (front blocks, origin doesn't)

Owned by `../../broken-access-control/references/role-matrix.md` §1 ("WAF-origin bypass") — SPF/`dig TXT` origin recovery plus every other origin-discovery vector, and the `curl --resolve` dial. Apply it here whenever a proxy/cache-manager or admin path is blocked at the edge; the ACL differential in section B above is what this file owns.

## D — Admin login / auth logic bypass

- a named product panel answering with a login form (Grafana, Jenkins, Kibana,
  phpMyAdmin, an appliance) -> **`../../infra-panels-default-creds/SKILL.md` owns
  the documented-default set and the post-login read.** Never guess a pair here:
  that skill carries the bounded vendor-default list, the lockout risk, and the
  rule that the "update password" prompt means it is still default. Recognition
  only in this file;
- a hardcoded token or credential in JS (PURSUE per
  `../../_shared/references/public-by-default-keys.md`);
- SQLi in the login (`' OR '1'='1'-- -`) -> hand to `sqli`;
- response-manipulation login (server ignores a client `authenticated:true`) ->
  confirm on a protected route, like MFA response manipulation;
- a `role`/`isAdmin` claim self-asserted in a forgeable JWT -> `jwt-attacks.md`;
- an alternate/legacy admin path (`/admin/v1`, `/internal`, `/_admin`) missing the
  middleware.

## Good evidence

- admin/customer-lookup endpoint returns one real record without a valid admin
  session (PII redacted);
- cache/proxy-manager endpoint reachable + one status/data page read despite ACL;
- canonical route denies while a normalized/alternate/absolute-URI form succeeds
  (the differential IS the proof);
- WAF blocks the path but the origin (via `--resolve`) serves it.

## Ladder discipline

Read one record to prove the class; never bulk-dump the admin table. Do not click
controls, purge caches, restart, deploy, or change state on admin/KVM/manager/
workstation panels — that is rung 5 — not attempted: d0x's approval before execution. If the panel exposes a live
control surface only (no readable data), capture the unauth-reachable state +
title/version as the boundary proof and rotate. Record any reachable admin surface
in the lead file under `targets/<program>/leads/`
(`../../_shared/references/output-contract.md`).
