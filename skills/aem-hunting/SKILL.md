---
name: aem-hunting
description: "Map Adobe Experience Manager, CQ5, Sling, dispatcher, and AEM Forms attack surfaces, apply AEM-specific URL and selector behavior, and route each reachable primitive to its owning vulnerability skill. Use when fingerprints or paths expose Communique, Sling, Jetty, client libraries, DAM, CRX, system console, QueryBuilder, dispatcher behavior, AEM Forms, or an AEM CVE. A product or version fingerprint alone is not a finding."
---

# AEM Hunting — the product router, not a seventh vuln class

Adobe Experience Manager (AEM, formerly CQ5) is a Java content runtime — Sling on
OSGi on Jetty — behind a dispatcher cache. This pack is organized by vulnerability
class, so this skill does **not** own SSRF, XXE, deserialization, EL/OGNL, stored
XSS, or the access-control bypass ladder. It owns two things nothing else can:

1. **Which class is worth probing on an AEM estate**, and
2. **the exact Sling URL to probe it with**.

Everything past that is a handoff, and the handoff is a self-invocation.

## The one rule this skill exists to enforce

**A version match is rung 0.** `Server: Communique-Dispatcher/4.3.6`, a `<meta
generator>`, "AEM 6.5.20 is in the APSB25-90 range" — none of these is a finding,
and d0x has two version-fingerprint-only submissions that closed informative with
zero bounty. Every CVE entry in this skill therefore ships with **the oracle that
must fire against that specific endpoint** before you write anything down. If you
cannot make the oracle fire, the target is not vulnerable — say so and rotate.

Read `../_shared/references/safe-ladder.md` §"Claiming a CVE" once per session.

## Read-on-demand references

- `references/fingerprint-and-sling.md` — is this AEM, which product line, which
  version; the Sling URL grammar table (the conceptual engine); the AEM-specific
  bypass **forms** and the verified `curl` behaviour for each. Open it first.
- `references/apsb25-90-catalog.md` — the Sites / Cloud Service endpoint catalog.
  Verified CVE table, per-endpoint request + oracle + rung + CONFIRMED/INFERRED
  label + `Converts?`. **This family is `PR:L`/`PR:H`, not pre-auth.**
- `references/forms-on-jee.md` — AEM Forms on JEE (APSB25-82): the three genuinely
  unauthenticated bugs, their fingerprints, and their safe first moves.
- `../_shared/references/safe-ladder.md` — how far to climb, and the CVE rung-0 rule.
- `../_shared/references/output-contract.md` — where results go: the funnel, the
  lead format, the `primitive|host|claim` dedup key, the severity enum.
- `../_shared/references/tooling.md` — `curl`, `jq`, `python3`, `ffuf`, `nuclei`,
  `interactsh-client` are present. `ysoserial` is **not** — the install line lives
  there and `references/forms-on-jee.md` needs it.

## Adobe's two positions, reconciled — state this once, then stop arguing it

The source material this skill was distilled from contradicts itself, and getting
this wrong costs a report. The defensible framing:

- **Adobe's product documentation** tells customers the dispatcher is the primary
  security control for a production publish instance, and that backend Sling
  resources must not be reachable from the internet. That is the customer's
  configuration contract.
- **Adobe's product security team does not treat a dispatcher-filter bypass as a
  vulnerability in AEM itself.** That is why the `nocanon` traversal and the
  path-parameter differential still work against current, fully patched Cloud
  Service: there is nothing for Adobe to fix, by Adobe's own classification.

Both are true, and together they say exactly one thing:

> **The dispatcher bypass is a finding against the CUSTOMER running AEM, never
> against Adobe — and only when it REACHED something.** On a customer program, cite
> Adobe's documented "dispatcher is the security control" position to anchor that a
> boundary was crossed; the severity then comes entirely from what sat behind it. On
> Adobe's own program, a bypass with nothing behind it will close as N/A.

So never file "I bypassed the dispatcher". File "I bypassed the dispatcher and read
X", where X is the finding, and X's owning skill writes the impact.

## Method

1. **Fingerprint** — `references/fingerprint-and-sling.md`. Confirm AEM, confirm
   the product line (Sites/Cloud vs Forms on JEE — they share almost nothing), pull
   the version. Record it in `notes/`; it is rung 0 and never leaves that file alone.
2. **Split by product line.** `/adminui/`, `/FormServer/`, `/soap/services/` present
   → Forms on JEE is co-hosted → `references/forms-on-jee.md` **first**: those three
   bugs are unauthenticated, which the Sites family is not.
3. **Pick a path the dispatcher blocks** — `/etc.json`, `/system/console`,
   `/bin/querybuilder.json`, a non-public `/content/<brand>/…` subtree — and walk the
   AEM bypass forms. The forms are in `references/fingerprint-and-sling.md`; the
   generalized method, the ordering ladder and the size-differential oracle belong to
   `../broken-access-control/references/edge-filter-bypass.md` — run that, do not
   re-derive it here.
4. **Confirm reach with an AEM-specific body oracle**, not a status code (table
   below).
5. **Walk the endpoint catalog** — `references/apsb25-90-catalog.md`. On production
   only two entries are rung 1; the rest write to a shared config path and are
   rung 5 — not attempted: ask d0x directly before executing.
6. **Get a low-privilege account before concluding "patched".** The whole APSB25-90
   family is scored `PR:L` — one item, CVE-2025-54250, is `PR:H`. An anonymous `401`/`403` means nothing. The
   author/contributor login comes from `targets/<program>/accounts.md`; if it is
   not there, ask d0x once for the exact required role; do not emit a blocker state.
7. **Hand the primitive to the class that owns it** (below). That skill produces the
   impact; this one does not.
8. **Dedup before you call it new:** `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.
9. **Validate** with `validation`, then `report-writing`.

## Body oracles — what proves you reached Sling

Status codes lie on an AEM estate; the body does not. Match on these:

| Body marker | Means |
|---|---|
| `{"jcr:primaryType":"cq:Page"…}` / any `jcr:` key | Sling rendered a JSON selector — you are past the dispatcher |
| `{"success":true,"results":N,"total":N,"more":…,"hits":[…]}` | QueryBuilder answered — the canonical AEM bypass signature |
| `org.apache.sling.api.servlets.HtmlResponse` in the body | You reached `SlingPostServlet` (a write endpoint) |
| `Granite UI` / `Coral.` in the HTML title or head | Author Touch UI reachable |
| `Sling Recent Requests`, `Apache Felix Web Console`, `Adobe Experience Manager Web Console` | OSGi console reachable — stop and treat as Critical |
| `Java/<ver>` User-Agent arriving at your OOB listener | The backend fetched your URL (SSRF or XXE fired) |
| Small static Apache 403 page, identical for every blocked path | Dispatcher block — the bypass is not working |

The **response-size differential** that separates "edge blocked" from "origin 404 on
a real backend" is a general technique and is owned by
`../broken-access-control/references/edge-filter-bypass.md` — take the two baselines
there, then come back and match on the bodies above.

## The `.infinity.json` false-positive gate

`.infinity.json` returning content is the single most over-reported AEM
"finding". Before it becomes a lead, all three must hold:

1. **The node is not already public.** `/content/<site>/<page>.infinity.json` on a
   page the site itself renders is *working as designed* — Sling is serving public
   content in a second format. Not a finding, no note, no mention.
2. **The dispatcher actually blocks the plain form.** If `/….json` returns 200
   without any bypass, there is no boundary to cross — the operator chose to publish
   it.
3. **Something non-public came back.** An `/etc` / `/conf` / `/home` / `/var` subtree,
   a `cq:Component` dialog, a `sling:resourceType` map of unlinked pages, a user or
   group node, or a property whose name matches
   `(pwd|password|secret|token|key|credential)` — that last case leaves this skill
   immediately for `exposed-secrets`.

Fail any of the three and it is rung 0. Note it as a dead end and rotate.

## Handoffs — this skill's real output

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill
and run it yourself, this session, carrying the raw primitive intact. If you stop at
the handoff, the chain ends and there is no finding.

| AEM surface you reached | Owner | What they add |
|---|---|---|
| `/services/accesstoken/verify` fetches your URL | `../ssrf-safe` | host-filter bypass ladder, IMDS/metadata reach, the caller-token exfil lift |
| Package-import XXE, SOAP XXE, any XML/SVG ingestion | `../ssrf-safe` (`../ssrf-safe/references/cve-tooling.md` owns the XXE→SSRF entity form) | the entity payloads, the OOB confirm, the file-read boundary |
| Forms `serDoc` base64+gzip Java bytes | `../deserialization-hunting` (`../deserialization-hunting/references/java.md`) | ysoserial gadget choice, the URLDNS rung-1 oracle, the benign-command escalation |
| `${7*7}`→`49` in a JSP, Struts devmode OGNL | `../rce-hunting` (`../rce-hunting/references/template-expression.md`) | engine confirmation, the OGNL/EL escalation, the safe command proof |
| OSGi service properties containing cloud keys, admin hashes, certificates | `../exposed-secrets` | identify the service by prefix, call its API read-only — that call is the deliverable |
| `experienceinfo.json.html` renders your markup to an author | `../xss` | the tagged OOB payload, the callback, the staff-session escalation |
| The dispatcher blocked it and you need it not to | `../broken-access-control/references/edge-filter-bypass.md` | the generalized bypass ladder, ordering, and the size-differential oracle |
| Reachable admin panel, default creds on a co-hosted ops service | `../infra-panels-default-creds` | the bounded documented-default set and the post-login read |
| The JS bundles that told you it was AEM | `../js-source-to-sink` | every remaining endpoint, secret and cloud marker in the bundles |

## Conversion table — grade honestly before spending a turn

| Claim | Converts? |
|---|---|
| Version banner / `Server: Communique` / "in the APSB25-90 range" | **No.** Rung 0, closes informative. Two of d0x's own. |
| Dispatcher bypass, only public page content behind it | **No.** Working as designed — see the `.infinity.json` gate. |
| Dispatcher bypass → node metadata only (`jcr:primaryType`, empty subtrees) | **Low.** Rarely worth the write-up on its own. |
| Dispatcher bypass → QueryBuilder returning non-public content nodes | **Yes, High** when the hits carry user data / config / secrets; Medium for structure only. |
| Dispatcher bypass → `/system/console` reachable and readable | **Yes, Critical.** Read one bundle list, stop, report. |
| `/services/accesstoken/verify` reaching IMDS or an internal service | **Yes, Critical** — but the report is `ssrf-safe`'s, not this skill's. |
| Package-import XXE, OOB only, no file read | **Medium.** Blind-only; do not inflate to Critical. |
| Stored XSS rendered to an author session | **Medium**, High if you demonstrate a staff-session consequence via `xss`. |
| EL → OSGi property dump containing live credentials | **Yes, Critical** — and the credential must then be exercised read-only by `exposed-secrets`. |
| Forms `serDoc` deserialization with a fired DNS oracle | **Yes, Critical.** |
| Forms `/adminui` OGNL (CISA KEV) | **Yes, Critical — but expect a duplicate.** Every scanner fires it. |
| Forms SOAP XXE with one file read | **Yes, High.** |
| GraphQL introspection enabled on a publish instance | **Medium at best**, and only with a field that returns non-public data. |

## Anti-patterns — do not spend tokens here

- **Modern Jetty (≥ 9.4.35) and current Cloud Service**: `..;/` is fixed. Selector
  smuggling, path parameters and the `nocanon` traversal are the live forms.
- **AEM as a Cloud Service (Skyline)**: much of the catalog is pre-blocked at Adobe's
  edge. Sling-level bypasses still have surface; the Forms bugs do not exist there at
  all (different product).
- **Post-auth XSS on an author instance you entered with supplied credentials**: low
  ROI, closes N/A without a pre-auth or cross-tenant angle.
- **`/system/console/configMgr` reachable** with no demonstrated read: half credit at
  best. Read one config or drop it.
- **A CVE id with no fired oracle.** The single most expensive habit in this class.
- **Reporting the bypass instead of the thing behind it** — see the reconciliation
  above. On Adobe's own program that is an N/A by construction.

## Tooling note

There is no AEM automation in this pack and none is shipped. Purpose-built AEM
bypass frameworks exist publicly, and `nuclei` carries `aem` / `default-login` /
`exposures` template families that cover parts of this surface — but every hit from
any of them is rung 0 until you re-fire the oracle by hand. Drive `nuclei` the way
`../infra-panels-default-creds/references/nuclei-driver.md` documents (host list in,
critical/high only, mandatory manual verification pass), and take the install and
availability facts for everything else — including `ysoserial`, which
`references/forms-on-jee.md` needs and which this host does **not** have — from
`../_shared/references/tooling.md`. Do not paste raw enumeration loops into a live
target; `ffuf-web-fuzzing` owns bounded discovery and honours the program's rate cap.

**The rule in one line:** fingerprint AEM, find the exact Sling URL that reaches the
class you want, fire that class's oracle, and hand the primitive to the skill that
turns it into impact — the version banner is never the finding.
