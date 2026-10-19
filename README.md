# huntline

An unauthenticated bug-bounty hunting pipeline: a line of specialized agents that takes a domain and
returns leads, then findings. Multi-provider over **subscription CLIs** (Claude Code via Max, Codex
via ChatGPT), never the API.

```
 Telegram (domain + scope)
      │
      ▼
 orchestrator (TS/Bun, this repo) ── sequences the line, paces to subscription quota
      │
      ├─▶ browser-operator   headless Chrome, UNAUTH: navigate, trigger SPA routes,
      │                       capture ALL JS (bundles, dynamic chunks, inline, source maps) ─▶ js/
      ├─▶ js-analyzer (GPT)   READS the JS (never greps), understands the logic,
      │                       emits one lead per primitive                                    ─▶ leads/
      │                       ── notify: "N leads ready"
      ├─▶ hunters ×3          Opus 4.6 + Opus 5.8 + GPT, each validates+exploits leads;
      │   (Phase 2)           a lead with a confirmed end-to-end PoC = a finding              ─▶ findings/
      ├─▶ validator           clean session: kills false positives, assigns CVSS
      │   (Phase 2)
      └─▶ reporter            first person, no em-dashes, PoCs re-verified                     ─▶ reports/
          (Phase 2)           ── notify: "N findings: idor x2, ssrf x1"
```

## Design principles

- **Flow over bureaucracy.** The funnel (`js/ → notes/ → leads/ → findings/ → reports/`) is a filing
  cabinet, not a set of approval gates. Nothing waits for a human to move between stages.
- **One hard gate:** a lead becomes a finding only with a proven end-to-end PoC that demonstrates
  impact — never theory — and the validator seals it in a clean session. One gate, at the end.
- **Two pull-notifications, never blocking:** "N leads", then "N findings + types". The bot never
  stalls waiting for a reply.
- **Sub-agents by design:** the js-analyzer may spawn reader sub-agents on a large corpus; hunters
  may spawn sub-agents to exploit. The only brake is a soft concurrency cap driven by subscription
  quota (the real limit), not approval.

## How this differs from `orquestator` (the 2025 attempt)

`orquestator` was a single-brain *ralph loop*: one Claude worker re-running the whole skills/CLAUDE.md
brain against a target, Claude-only, Python. huntline is a **multi-provider assembly line of
specialized agents** that does its own unauthenticated recon (browser-operator) instead of consuming
a pre-collected jxscout corpus. Carried over from the old design: adversarial validation, the JSONL
log as source of truth, env-driven config, a `doctor` preflight.

## Run

```sh
cp .env.example .env    # fill TELEGRAM_* to use Telegram; optional otherwise
bun run doctor          # verify chrome + both CLIs by execution
bun run smoke           # browser-operator self-test on localhost (no quota, no external traffic)
bun run hunt example.com --crawl-only      # crawl only, no subscription quota
bun run hunt example.com scope: *.example.com   # full phase-1 run (crawl -> js-analyzer -> leads)
bun run serve           # Telegram ingress: message the bot a domain to start a run
```

Runs land in `runs/<id>/` with the funnel directories and `logs/run.jsonl`.

## Status

Phase 1 wired: browser-operator + js-analyzer + Telegram + orchestrator spine. Phase 2 (hunters,
validator, reporter) is next. The js-analyzer methodology in `prompts/js-analyzer.md` is a first cut;
it gets refined by porting the real hunting skills (decoupled from the old `_shared` contracts).
