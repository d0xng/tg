import { crawl } from "./agents/browser-operator.ts";
import { runJsAnalyzer } from "./agents/js-analyzer.ts";
import { runHunters } from "./agents/hunter.ts";
import { notify } from "./telegram.ts";
import { jsonl, log, err as logErr } from "./log.ts";
import { timeouts } from "./config.ts";
import { Run } from "./run.ts";

// The orchestrator sequences the assembly line for one run. Phase 1 wired here: crawl -> js-analyzer
// -> notify "N leads". Phase 2 appends: hunters -> validator -> reporter -> notify "N findings + types".
// The funnel is a filing cabinet, not a set of approval gates: each stage writes its directory and
// the next stage reads it. Nothing waits on a human except the two pull-notifications.

export interface OrchestrateOpts {
  crawlOnly?: boolean; // dev: stop after the browser-operator (no subscription quota spent)
}

export async function orchestrate(run: Run, opts: OrchestrateOpts = {}): Promise<void> {
  jsonl(run.logFile, { event: "run:start", domain: run.state.domain });
  try {
    // Stage 1 — browser-operator (unauthenticated crawl + JS capture)
    run.setStage("crawling");
    const { jsFiles } = await crawl(run.state.startUrl, run.sub("js"), {
      idleNoNewJsMs: timeouts.crawlIdleMs,
      maxMs: timeouts.crawlMaxMs,
      maxPages: timeouts.crawlMaxPages,
    });
    run.state.counts.jsFiles = jsFiles;
    run.save();
    jsonl(run.logFile, { stage: "crawling", event: "crawl:done", jsFiles });
    log(`run ${run.state.id}: crawl done, ${jsFiles} JS artifacts`);

    if (opts.crawlOnly) {
      run.setStage("done");
      await notify(`crawl done on ${run.state.domain}: ${jsFiles} JS artifacts (crawl-only)`);
      return;
    }

    // Stage 2 — js-analyzer (read, emit leads)
    run.setStage("analyzing");
    const leads = await runJsAnalyzer(run);
    await notify(`leads ready on ${run.state.domain}: ${leads} lead${leads === 1 ? "" : "s"} (run ${run.state.id})`);

    if (leads === 0) {
      run.setStage("done");
      return;
    }

    // Stage 3 — hunters (validate + exploit leads into findings)
    run.setStage("hunting");
    const findings = await runHunters(run);
    run.setStage("done");
    await notify(
      `findings on ${run.state.domain}: ${findings} candidate${findings === 1 ? "" : "s"} (pending validation) -> ${typesSummary(run)}`,
    );

    // Phase 2 remaining (next): validator (clean session seals each finding + CVSS) then reporter
    // (first person, no em-dashes, PoCs re-verified). The notify above becomes "N validated findings"
    // once the validator gate is wired.
  } catch (e) {
    run.state.error = String(e);
    run.setStage("error");
    jsonl(run.logFile, { event: "run:error", error: String(e) });
    logErr(`run ${run.state.id} failed:`, e);
    await notify(`run error on ${run.state.domain}: ${String(e)}`);
  }
}

// Used by the findings notification in Phase 2: "idor x2, ssrf x1".
export function typesSummary(run: Run): string {
  const entries = Object.entries(run.state.findingsByType);
  if (!entries.length) return "none";
  return entries.map(([k, v]) => `${k} x${v}`).join(", ");
}
