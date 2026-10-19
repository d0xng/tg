---
name: resource-abuse
description: "Validate missing entitlement, metering, credit, plan, or quota enforcement and, only when policy permits, bounded resource or cost amplification. Use when a paid feature, generation endpoint, export or render job, retry mechanism, credit balance, plan field, or quota response may be enforced only by the client or inconsistently by backend routes. A standalone absence of rate limiting is not a finding; never degrade availability."
---

# resource-abuse — prove a missing entitlement check with a dollar figure, never by degrading availability

## Step 0 — the policy gate (do this before anything else)

**Resource-exhaustion / DoS is excluded by policy in most H1 and Bugcrowd programs, and
`../validation/references/auto-discard.md` row 16 auto-discards "rate-limiting absence on a
non-authentication endpoint" outright.** So before you spend a request:

1. Read the program's policy in `targets/<program>/CLAUDE.md`. Search it for: `denial of
   service`, `DoS`, `rate limit`, `resource exhaustion`, `volumetric`, `automated scanning`.
2. If DoS/resource-exhaustion is excluded — and it usually is — **skip §B entirely** and
   hunt only §A (entitlement / metering / cost amplification), which is a *missing
   authorization check with a dollar figure attached*, not a DoS class. §A stays in scope
   even when DoS is excluded.
3. If the program explicitly pays for resource-abuse, §B is open — still bounded.

"No rate limit" is **never the headline** of a report out of this skill. It is supporting
evidence for a §A finding at most.

## Mission

**§A (primary) — prove a billable or plan-gated action ran for an identity that was never
entitled to it.** This is a missing server-side authorization check with a quantifiable
dollar cost. It converts; it is not a DoS class; it survives the auto-discard table.

**§B (secondary, policy-gated) — bounded resource amplification**: unbounded state growth,
parser/renderer cost, cache-key poisoning, notification/webhook amplification. Only after
Step 0 clears it.

**A single accepted request is rung 0.** The finding is the proven missing control plus
its realistic impact — never "the server let me do it once."

Climb the shared safe ladder (`../_shared/references/safe-ladder.md`): read-only baseline
first → own/synthetic context → minimal bounded proof → UAT/staging if RoE requires →
state realistic impact by inference. Take the lowest rung that proves the missing control;
never load-test to "show scale."

### §A — the three mechanisms, each with its oracle

1. **Client-side meter.** The UI decrements a credit/quota balance; the API never does.
   *Oracle:* read the balance endpoint → invoke the billable action once → read the balance
   again. **A successful generation with an unchanged balance is the proof.** Repeat once to
   confirm it is not a caching artifact — then stop (safe-ladder rung 2b).

   **First prove that the balance you are reading is the balance this action bills.** An
   unmoved meter is worthless evidence if it was never the governing meter, and reading the
   wrong counter has already cost this rig a finding. Three things establish it, cheapest
   first:

   - **the response header of the billable call.** Metered platforms commonly answer with
     their own verdict — `x-credits-consumption-status: quota_available`,
     `x-access-user-context: gc_cons_status="…", gc_credit_type="<the pool>"`. That header
     is the server stating which pool it evaluated and that it found quota. A named pool
     that then does not decrement is the whole finding in two requests, and it is much
     stronger than a before/after pair because it removes the "that endpoint isn't metered"
     answer entirely. Dump full response headers on the billable call, always.
   - **the vendor's own documentation**, per §A-severity below — it names the feature and
     the pool together.
   - **an entitlement read** (`/profile`, `/entitlements`) showing the identity holds no
     paid product, so the free pool is the only one that could apply.

   **Then run the paid-tier control.** Repeat the unmoved-meter observation on a *funded*
   account if you have one — an enterprise/paid identity with a large balance whose meter
   also stays put. That kills the "the free tier is deliberately ungated / promotional"
   reading, which is otherwise the most common way this class is closed as by-design.
2. **Unchecked gateway.** A plan-gated model / action / feature list is served to every
   caller, and the gateway never verifies entitlement. *Oracle:* enumerate the gated list
   from the JS (`js-source-to-sink`), invoke a documented Pro-only entry from a **free**
   account you own, capture the full output. Decode your own token first and show a
   free/consumer tier with no paid org attached — that is the convincer.
3. **Enforcing sibling.** Find the neighbouring action that DOES return
   `403 not entitled` / `plan required` for the *same* caller. "Sibling X enforces, Y does
   not" is what proves a missing check rather than a by-design free feature. This rule is
   owned by `../tenant-isolation/references/oracles-and-leaks.md` §"The enforcing-sibling
   convincer" — reuse it, do not rewrite it. Its entitlement-gated variant (a neighbouring
   paid/compute route returning **403 not-entitled** for the same identity) is exactly this
   case.

### §A — recognize the limit-overrun shape: it is a RACE, not a metering bug

Some §A gates fail only under concurrency: the check and the decrement are two statements, so N
simultaneous requests all read the pre-decrement value. Recognize it — do not treat it as a
missing check, and do not test it sequentially:

- **seat / member overrun** — invite past the plan's seat count, N invites in flight at once;
- **credit or coupon double-spend** — one balance, one code, or one referral bonus redeemed twice;
- **quota reset / free-tier reload** — the counter is re-read after the reset window opens;
- the tell in the response is a **balance that went negative, or a count above the documented
  cap** — sequential requests return the correct `403 not entitled` while concurrent ones do not.

**Method, bounds, and the concurrency oracle are owned by
`../broken-access-control/references/race-conditions.md`** — open it and run it there. It is
bounded to 2–3 concurrent requests on an account the operator owns, the state is reverted
immediately, and a race against a financial or payment action is never fired — it asks d0x directly before executing. Do not
improvise a concurrency proof from this file.

### §A — severity is anchored on documentation, not on request count

Quote the vendor's own pricing page or docs stating the feature costs credits or requires a
plan, and frame the impact financially: "$X/mo plan bypassed", "N credits consumed for
free", "a Pro-only model invoked from a free account". That framing is what lifts this out
of the "no rate limit → auto-discard" bucket.

**Converts: High** — a documented entitlement gate plus quantifiable billed compute; it
scores at or above a bare cross-tenant read. Same-tenant only, no billing gate documented →
Medium.

**Corpus case:** `3750778` — `h1/reports/3750778-adobe-triaged.md` (medium · triaged). Worth
reading for what carried it: a free identity with no products, the vendor FAQ quoted stating
that this exact feature costs one credit per generation, the server's own
consumption-status header naming the pool, and the balance unchanged afterwards. Note that
it also fired 20+ generations — the arsenal's 2–3 bound stands, because the impact section
that converted it argues from the **published plan price**, not from the request count. The
extra generations added evidence of nothing.

### §A — non-destructive boundary

`../_shared/references/safe-ladder.md` **rung 2b**: your own free account, 2–3 invocations,
never bulk-generate to show scale, never bill a victim tenant beyond a single invocation and
only after the read-side cross-tenant proof exists.

### §A — routing

If the entitlement key is an **org/tenant header**, the cross-tenant half is owned by
`../tenant-isolation/references/tenant-vectors.md` §2 — recognize it here, prove the
cost amplification, and run `tenant-isolation` for the tenant boundary.

## §B — bounded resource amplification (only if Step 0 cleared it)

Find whether one ordinary user can make the application spend disproportionate
resources, create unbounded state, poison cacheable content, or trigger unsafe
parser/renderer behavior.

Prefer proving:

- no per-user quota;
- no idempotency or duplicate suppression;
- expensive background job creation;
- storage growth from small repeated objects;
- notification or webhook amplification;
- cache/key explosion;
- export/report generation without cost controls;
- missing server-side size limits or pathological latency;
- parser or renderer cost from small but complex rich-text inputs;
- insufficient validation of simple-looking fields such as email or username;
- malformed domain-specific input that causes isolated worker failure;
- cache poisoning that blocks static assets, pages, widgets, or CDN resources.

Rate-limit absence on a non-authentication endpoint is **supporting evidence only** —
`../validation/references/auto-discard.md` row 16 discards it standalone. Never emit it as a
finding.

## Triggers

Apply this skill when recon finds endpoints or flows that:

- gate a model, action, export, seat, integration, or feature behind a plan, credit
  balance, or entitlement flag;
- return quota, rate-limit, retry, job, cache, storage, credit, or billing metadata;
- create drafts, saved searches, exports, reports, invoices, uploads, comments,
  notifications, webhooks, API tokens, sessions, jobs, or background tasks;
- enqueue email, PDF generation, indexing, import, sync, scan, backup, media
  processing, LLM inference, or webhook delivery;
- accept repeated identical creates without idempotency;
- accept large free-text fields, names, descriptions, titles, draft bodies,
  comments, notes, filters, search terms, JSON blobs, markdown, or HTML-like
  content;
- render markdown, rich text, Mermaid/diagram syntax, mentions, emoji, embeds,
  URLs, link unfurling, templates, or HTML sanitization;
- accept email, username, display name, slug, phone, address, invitee,
  recipient, or webhook URL before strict length and format validation;
- parse domain-specific blobs or encoded objects;
- serve cacheable pages, CDN assets, static resources, product widgets,
  documentation pages, image/script/CSS files, redirects, or API responses;
- vary behavior based on path normalization, slash/backslash handling, encoded
  segments, host-like headers, forwarded headers, query params, language/device
  headers, or error responses;
- expose expensive filters, search queries, sort combinations, pagination,
  graph traversals, or aggregation endpoints.

## Read-on-demand references

Choose only the relevant reference after mapping the surface. All five serve §B.

- `references/payload-growth.md` — oversized create/update fields and bounded
  payload ladders.
- `references/parser-renderer.md` — markdown, rich text, Mermaid, link unfurl,
  template, embed, and renderer cost checks.
- `references/simple-field-length.md` — email, username, slug, phone, recipient,
  webhook URL, and similar validation paths.
- `references/malformed-domain-object.md` — encoded objects, signed envelopes,
  import formats, protocol messages, and crash-like parser signals.
- `references/cache-poisoning-denial.md` — CDN/cache key mismatch, canonical URL
  poisoning, static asset denial, path/header normalization issues. Rung 2b bounds
  it only on a nonce/owned path; anything that could land in a **shared** cache
  entry is rung 5 (not attempted: ask d0x directly before executing). If an *authenticated page* lands in a public
  cache entry, that is cache **deception** — hand it to
  `../tenant-isolation/references/cache-deception.md`, which owns that class.
- `../_shared/references/output-contract.md` — where results go: the
  notes/leads/gadgets/findings funnel, the lead format, the `primitive|host|claim`
  dedup key, and the severity enum.

## Safety rules

- Only use accounts and objects controlled by the operator.
- Keep proof bounded. Default maximum is 3 to 5 requests unless the program
  explicitly authorizes more.
- Use one worker and a visible delay between requests.
- Stop immediately on latency spike, 429, 5xx, queue backlog, user-visible
  degradation, or any sign of shared-service pressure.
- Never attempt to exhaust disk, memory, CPU, queues, email systems, webhooks,
  billing balances, CDN caches, or third-party integrations.
- Never modify, delete, corrupt, or overwrite third-party data.
- If a write-like method is needed, use only synthetic records that the operator
  owns and clean them up when cleanup is safe and supported.
- For cache checks, use a unique nonce, low-traffic test path, owned
  shop/page/resource, or harmless static asset variant.
- For crash-like parser checks, prefer source review, local reproduction,
  staging, testnet, or vendor sandbox before production.

## Algorithm

1. Run Step 0. If DoS is excluded, §A only.
2. **§A first:** map plan-gated / credit-metered / quota-bearing actions. Decode your own
   token, read the balance or entitlement endpoint, and locate the enforcing sibling.
3. Prove §A with the oracle for its mechanism: invoke once, re-read the meter, quote the
   vendor's pricing page. Stop at 2–3 invocations.
4. **§B (if cleared):** map candidate create/process/cache/parser endpoints and rank by
   server-side cost and blast radius.
5. Identify natural controls: quota, rate-limit headers, duplicate handling,
   max object count, max payload size, parser complexity limits, cache keys,
   max job count, and cleanup behavior.
6. Choose the relevant reference and follow its bounded method.
7. Send one baseline request from the operator account or safe low-impact URL.
8. Run the smallest safe proof: tiny repeat set, tiny payload ladder, one
   parser variant, or one cache-key variant.
9. Check whether limits appear and whether impact is real.
10. Write the lead only when evidence shows a missing entitlement/cost/cache/parser
    control and realistic impact.

## Confirmation oracles

Strong signals:

- a billable action succeeds while the credit/quota balance is unchanged;
- a documented Pro-only model/feature/export runs from a free account you own;
- a neighbouring action returns `403 not entitled` / `plan required` for the same
  caller while the tested one returns 200;
- multiple duplicate objects accepted with no idempotency key or limit;
- repeated jobs queued from the same user/action with no cooldown;
- export/report/PDF/media generation accepted repeatedly;
- account-local object count grows without quota;
- retry endpoints trigger repeated delivery attempts;
- oversized create payloads cause disproportionate latency, storage growth, or
  downstream processing without limits;
- rich-text/parser inputs cause disproportionate render cost without complexity
  limits;
- simple fields reach expensive validation paths before max-length enforcement;
- malformed domain objects produce fatal errors instead of clean validation
  failures;
- a crafted cache variant causes canonical cache hits to serve an error, wrong
  object, unavailable asset, or poisoned response.

Weak signals:

- a single successful create;
- one uncached 404/500;
- a 200 response without proving state growth, job creation, cache poisoning,
  parser cost, or an unchanged meter;
- normal use with documented limits;
- client-side-only controls when the backend still enforces limits.

Not findings:

- limits trigger before meaningful impact;
- only the operator's UI becomes cluttered;
- proof requires high volume or sustained load;
- impact depends on harming availability during testing;
- a likely crash trigger was repeated on production after the first signal;
- cache poisoning was tested on high-traffic shared URLs without explicit
  approval.

## Severity guidance

- **high**: §A entitlement/metering bypass with a documented plan gate and a quantified $
  impact — the class this skill leads with.
- low: account-local clutter with weak impact.
- medium: unbounded per-user object/job creation with plausible storage or
  operational cost.
- **high** (§B): clear amplification, expensive backend processing, notification/webhook
  abuse, cache poisoning of important resources, or cross-tenant/shared resource
  pressure proven safely.
- critical: only with program-safe proof of severe business impact and no
  availability degradation during testing.

## Evidence checklist

Capture as you go into `targets/<program>/notes/`, then write the lead per
`../_shared/references/output-contract.md` with **Group:** `logic-misconfig`:

- baseline request and response;
- exact endpoint, method, field, object type, cache URL, or parser surface;
- **§A**: the token decode showing your free/consumer tier, the meter/balance read
  before and after, the invocation output, the enforcing sibling's `403`, and the
  vendor doc/pricing URL that anchors the dollar figure;
- **§B**: bounded proof parameters — request count, delay, payload size, complexity
  variant, or cache-key variant;
- timing, response status, body hash/snippet, headers, object count, job count,
  cache headers, queue ID, or storage evidence;
- the missing control, named: entitlement, quota, rate limit, idempotency, size
  limit, complexity limit, clean validation, or cache-key separation;
- cleanup status for owned objects;
- stop condition, especially for 5xx/timeout/reset/cache-poisoning signals.

Two grading rules that keep these leads honest: do not claim DoS from a single slow
response without a realistic cost or availability argument, and do not claim cache
poisoning unless canonical cache hits serve the poisoned response. High/critical claims
go through `validation` first.

## Handoffs

**Handoffs are self-invocations.** "Hand to `<skill>`" means *you* open that skill and run it yourself, in this same session, carrying the raw primitive intact. Nobody else picks the lead up — if you stop at the handoff, the chain ends there.

- `tenant-isolation`: the entitlement key is an org/tenant header — the cross-tenant half is
  owned there (`../tenant-isolation/references/tenant-vectors.md` §2).
- `broken-access-control`: the limit only fails under concurrency (seat overrun, credit
  double-spend, quota reset) — the race method is owned by
  `../broken-access-control/references/race-conditions.md`.
- `js-source-to-sink`: enumerate the plan-gated model/action list from the bundles before
  probing it.
- `ai-injection` / AI surfaces: LLM-inference and generative-credit endpoints are the
  highest-yield §A surface.
- `idor-bola`: object ownership or cross-account visibility.
- `ffuf-web-fuzzing`: parameter discovery is needed before testing.
- `deserialization-hunting`: serialized/parser object trust-boundary signals.
- `validation`: uploads, exports, generated files, high/critical claims,
  crash-like signals, or cache poisoning with shared blast radius.
- `report-writing`: only after `validation` accepts proof quality.

## Dedup

Before promoting a resource-abuse lead to a finding, dedup against d0x's submitted corpus
and this session's `findings/`.

Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.

The *technique* (entitlement oracle, payload ladder, parser-cost variant, cache-key poison,
own-session repeat) is reusable across targets; a specific submitted finding is not
re-reportable.

**The rule in one line:** prove the missing entitlement or limit with the smallest bounded,
owned-context action and a documented dollar figure, then hand the impact off — never
degrade availability to "show scale," and never stop at a single accepted request.
