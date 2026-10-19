# Output Contract — where findings go

Shared reference. Every hunting skill writes results this way instead of inventing its own format.

A bug that lives only in your closing summary is **lost**. The summary is read once and discarded; the files below survive context compaction, get re-read next session, and are what a report is built from. **Write to disk as you go, not at the end.**

Write every operational artifact and all explanatory prose in English. Preserve raw code, paths, identifiers, secrets, requests, responses, commands, and other evidence verbatim.

---

## The funnel

Everything lands under `targets/<program>/`, created by `/setup`. Root `AGENTS.md` owns the full Codex layout; the funnel stages are:

```
targets/<program>/
├── CLAUDE.md    program identity, scope, policy, peculiarities
├── notes/       raw exploration: requests, responses, observations, dead ends
├── leads/       something that may lead somewhere — not yet proven
├── gadgets/     reusable primitives: oracles, working payloads, id->user maps
├── findings/    confirmed bugs with proof, pending report
└── reports/     submitted
```

Flow is `notes -> leads -> gadgets -> findings -> reports`. It is a funnel: most notes never become findings, and that is correct. Never skip a stage to make progress look better.

Two working directories sit alongside the funnel and are **inputs to tools, not funnel stages** — create them on demand, do not treat them as evidence:

- `js/` — the JavaScript collected for this target (jxscout writes here).
- `wordlists/` — target-derived lists and raw request templates built for `ffuf` (`js-paths.txt`, `baseline.txt`, `req.txt`). Persist them so a later pass reuses them instead of re-deriving.

---

## When to write what

| you have | write to | file naming |
| --- | --- | --- |
| a request/response worth remembering, or a dead end | `notes/` | `<surface>-<date>.md` |
| a JS security-relevant signal whose chain is incomplete | `leads/` | `js-lead-ledger-<date>.md` seed row |
| an unproven but actionable suspicion with a next step | `leads/` | `<class>-<host>-<short>.md` |
| a primitive that will work again, here or elsewhere | `gadgets/` | `<what-it-does>.md` |
| a proven bug that passed `validation` | `findings/` | `<severity>-<class>-<host>.md` |

**Write a dead-end note before you rotate angles.** One line is enough (`invoice id is a signed opaque token, not sequential — id-swap dead`). It stops future-you re-walking the same ground.

---

## Two capture states inside `leads/`

JavaScript analysis is capture-first. A code-backed signal must not disappear merely because a later file, request contract, or attacker-controlled source has not been found yet.

### Seed lead — preserve now, enrich later

Append each security-relevant JS signal immediately to `leads/js-lead-ledger-<date>.md`:

```markdown
| ID | Source | Raw evidence/value | Category | Why suspicious | Missing link | Owning skill | Priority | Status |
```

- Use a stable ID (`JS-0001`, `JS-0002`, ...), exact `file:line`, and literal evidence or raw value.
- `Why suspicious` states the concrete security behavior; `Missing link` states exactly what remains unresolved instead of using `unknown`, `TBD`, or generic filler.
- Valid statuses are `seed-untriaged`, `seed-enriched`, `validation-pending`, `closed-with-control`, and `promoted`.
- A single location gets multiple rows when it supports independent vulnerability classes. Exact duplicates may share a row only if every location is retained.
- Endpoint inventories and general notes do not replace seed rows. Root-level silent exclusions remain silent and do not get rows.

A seed is deliberately incomplete. Enrich it by reading surrounding functions, callers, guards, wrappers, and sibling implementations. Do not promote or close it based only on the initial snippet.

### Actionable lead — full template

**The format is `templates/lead.md` at the rig root.** Do not invent a shorter one and do not copy a shape out of a skill: `js-miner`, the downstream exploitation skills, `validation`, and `report-writing` all rely on the same fields. A lead in any other shape forces the next stage to rediscover evidence.

The header a lead is born with:

```markdown
# <slug>

**Source:** <exact-js-file>:<line-or-range> · **Group:** <secrets|cloud|oauth-auth|client-side|idor-bola|bac-tenant|business-logic|server-sink|third-party> **Skill:** <owning skill> · **Priority:** <critical|high|medium|low> **Created:** <iso-date> · **Status:** lead-pending-validation **Claim:** <precise falsifiable claim written in English>
```

The remainder is the complete English structure in `templates/lead.md`. It must include exact code location and context, the source-to-transformations/guards-to- sink trace, actor/victim/object/role/tenant model, request contract, exploitation hypothesis, priority rationale, PoC sketch, controls, safe stopping point, numbered next steps, prerequisites/blockers, handoff, and dedup key. Raw values remain verbatim and unredacted in the working lead; report redaction happens later.

The machine-readable `Primitive`, `Delivery`, and `Evidence` labels remain unchanged and every one must contain a concrete English value. A generated actionable lead with `unknown`, `TBD`, `TODO`, an empty section, an angle-bracket placeholder, or vague filler is a protocol violation. Continue reading related code until it is actionable. If a concrete code-backed security signal still lacks a complete claim, keep it as a seed with its exact missing link instead of dropping it or fabricating certainty.

**What live exploitation and validation append is not optional.** Complete the English validation sections for observations, verdict, the request that produced it, why that request tests this claim, discriminating and positive controls, new ideas, and untested hypotheses. The untested list preserves the remaining attack surface for the next session.

The **dedup key is `primitive|host|claim`** — the root `AGENTS.md` owns it. Keep the claim string stable across sessions; if you reword it, the same bug reads as new and you waste a validation pass on it.

## Never close empty

If you found nothing provable, that is a legitimate outcome — but say **what you tried and what resisted**, per boundary, in `notes/`. "Nothing found" with no angle list is indistinguishable from "did not look" and forces a full re-hunt.

Every code-backed security-relevant JS signal belongs in a seed; every plausible vulnerability with a concrete trace and falsifiable exploitation hypothesis belongs in an actionable lead before live validation. Never inflate a seed into a vulnerability or finding to make progress look better. The pack's [public-by-default-keys.md](public-by-default-keys.md) SKIP list, and the operator's anti-pattern list (CORS, missing headers, cookie flags, self-XSS, user enumeration, theoretical findings), are **silent** skips after confident classification: no note, no lead, no mention. An unfamiliar key or construct is captured first and removed only after it is positively identified as an explicit silent exclusion.

---

## Severity

Use the anchors in `../../validation/references/severity-anchors.md`. File severity from **proven** evidence only — the impact you actually demonstrated, not the one the primitive could reach. A `validation` verdict, once issued, binds the severity; do not re-rate upward when writing the report.

Enum, exactly: `info` `low` `medium` `high` `critical`. Nothing else.

---

## Before promoting a lead to a finding

1. It reproduces from a clean session (fresh token, second run).
2. It passed the `validation` skill with `VALID:<severity>` and has no unresolved proof route.
3. Dedup before you call it new: `rg -i '<primitive> <host>' ~/Desktop/skills/personal-corpus/h1/index.md ~/Desktop/skills/personal-corpus/bugcrowd/index.md`, and — when the program has one — its live ledger under `targets/<program>/reports/`, which wins over any stale export. A match on the same primitive + same host is CLOSED: rotate to the next angle.
4. Its proof sits at the lowest rung of [safe-ladder.md](safe-ladder.md) that proves the class.

Then hand it to `report-writing`.
