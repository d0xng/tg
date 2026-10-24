import { readFileSync } from "fs";
import { join } from "path";
import { crawl } from "./agents/browser-operator.ts";
import { runJsMiners } from "./agents/js-miners.ts";
import { enrichCorpus } from "./agents/js-enrich.ts";
import { runHunters } from "./agents/hunter.ts";
import { runValidator } from "./agents/validator.ts";
import { runReporter } from "./agents/reporter.ts";
import { notifyMd, sendDocument, mdEscape } from "./telegram.ts";
import { jsonl, log, err as logErr } from "./log.ts";
import { timeouts } from "./config.ts";
import { killRunProcesses } from "./util/procs.ts";
import { Run } from "./run.ts";

// The orchestrator sequences the full assembly line for ONE host and reports to Telegram at every phase
// boundary (English, no emoji): crawl -> js-miners -> hunters -> validator -> reporter. The one-shot
// `hunt` path and the Telegram/recon path both call this, so both go end to end to the reports.

export interface OrchestrateOpts {
  crawlOnly?: boolean; // dev: stop after the browser-operator (no subscription quota spent)
}

const EMDASH = "—";
const DOT = "·";
const BULLET = "•";

// First markdown heading of a funnel .md (the finding/lead title), else the filename.
function titleOf(run: Run, sub: "leads" | "findings", file: string): string {
  try {
    const txt = readFileSync(join(run.sub(sub), file), "utf8");
    const h = txt.split("\n").find((l) => l.trim().startsWith("#"));
    if (h) return h.replace(/^#+\s*/, "").trim();
  } catch {
    /* fall through */
  }
  return file.replace(/\.md$/, "");
}

export async function orchestrate(run: Run, opts: OrchestrateOpts = {}): Promise<void> {
  const dom = () => mdEscape(run.state.domain);
  jsonl(run.logFile, { event: "run:start", domain: run.state.domain });
  // A stage whose agents never produced a result has told us NOTHING about the target, so the run must
  // not end `done`. Called before every "nothing here" exit and before the final done: that is what
  // stops a 429 session limit from being filed as "no bugs on this target", which is exactly what
  // happened to six uber.com candidates on 2026-10-22. The throw lands in the catch below, which marks
  // the run `error` and names the reason, and run.json keeps the list so the right src/*-run.ts can
  // finish the job once the limit resets.
  const bailIfAgentsFailed = (stage: string): void => {
    const f = run.state.failures ?? [];
    if (!f.length) return;
    throw new Error(
      `${stage}: ${f.length} agent invocation(s) produced no result (${f.join("; ")}). The stage is INCOMPLETE, not negative: re-run it with the matching src/*-run.ts once the limit resets.`,
    );
  };
  try {
    // Stage 1 - browser-operator (unauthenticated crawl + JS capture + chunk pre-fetch)
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
    await notifyMd(`*Crawl done* ${EMDASH} ${dom()}\n${mdEscape(`${jsFiles} JS artifacts`)}`);
    if (opts.crawlOnly) {
      run.setStage("done");
      return;
    }

    // Stage 2 - js-miners (parallel readers emit leads)
    run.setStage("analyzing");
    // Enrich the corpus first: recover the original sources from any .map the crawl captured (the
    // crawler has always downloaded them and nothing ever read them), and beautify what is left, so
    // a miner reads named source instead of one 5 MB line. Never fatal: a corpus that cannot be
    // enriched is still the corpus the crawl produced.
    try {
      const enriched = await enrichCorpus(run);
      if (enriched && enriched.maps.written) {
        await notifyMd(
          `*Source maps reversed* ${dom()}\n${mdEscape(
            `${enriched.maps.written} original files from ${enriched.maps.withContent} maps`,
          )}`,
        );
      }
    } catch (e) {
      logErr(`[js-enrich] stage failed, continuing with the raw corpus: ${(e as Error).message}`);
    }
    const leads = await runJsMiners(run);
    const leadFiles = run.listMd("leads");
    await notifyMd(`*Analysis done* ${EMDASH} ${dom()}\n${mdEscape(`${leads} lead${leads === 1 ? "" : "s"}`)}`);
    if (leadFiles.length) {
      const body = [
        `# Leads ${EMDASH} ${run.state.domain}`,
        "",
        `${leadFiles.length} lead${leadFiles.length === 1 ? "" : "s"}`,
        "",
        ...leadFiles.map((f, i) => `${i + 1}. ${f.replace(/\.md$/, "")} ${EMDASH} ${titleOf(run, "leads", f)}`),
      ].join("\n");
      await sendDocument(`leads-${run.state.domain}.md`, body);
    }
    if (leads === 0) {
      bailIfAgentsFailed("analyzing");
      run.setStage("done");
      return;
    }

    // Stage 3 - hunters (exploit leads into candidate findings)
    run.setStage("hunting");
    await runHunters(run);
    const findingFiles = run.listMd("findings");
    if (!findingFiles.length) {
      bailIfAgentsFailed("hunting");
      await notifyMd(`*Hunting done* ${EMDASH} ${dom()}\n${mdEscape("no candidate findings")}`);
      run.setStage("done");
      return;
    }
    const findingLines = findingFiles.map((f) => `${BULLET} ${mdEscape(titleOf(run, "findings", f))}`).join("\n");
    await notifyMd(
      `*Hunting done* ${EMDASH} ${dom()}\n${mdEscape(`${findingFiles.length} candidate finding${findingFiles.length === 1 ? "" : "s"}:`)}\n${findingLines}`,
    );

    // Stage 4 - validator (clean-session re-verification + CVSS; kills false positives)
    run.setStage("validating");
    const v = await runValidator(run);
    const extra =
      (v.skipped ? ` ${DOT} ${v.skipped} skipped (low/info)` : "") +
      (v.failed ? ` ${DOT} ${v.failed} NEVER VALIDATED (agent produced no result)` : "");
    await notifyMd(
      `*Validation done* ${EMDASH} ${dom()}\n${mdEscape(`${v.valid} confirmed ${DOT} ${v.invalid} dropped${extra}`)}`,
    );
    if (v.valid === 0) {
      // Before concluding there is nothing to report: if validators never ran, `valid === 0` is a
      // statement about the quota, not about the findings.
      bailIfAgentsFailed("validating");
      run.setStage("done");
      return;
    }

    // Stage 5 - reporter (submission-ready reports, re-verified; sent as .md attachments)
    run.setStage("reporting");
    await runReporter(run);
    const reportFiles = run.listMd("reports");
    await notifyMd(
      `*Report ready* ${EMDASH} ${dom()}\n${mdEscape(`${reportFiles.length} report${reportFiles.length === 1 ? "" : "s"} attached`)}`,
    );
    for (const f of reportFiles) {
      try {
        await sendDocument(f, readFileSync(join(run.sub("reports"), f), "utf8"));
      } catch {
        /* a failed attachment must not fail the run */
      }
    }
    // Everything that could be produced has been. If any invocation along the way produced no result,
    // this run is incomplete and says so instead of reading as a clean finish.
    bailIfAgentsFailed("run");
    run.setStage("done");
    jsonl(run.logFile, { event: "run:done", findings: findingFiles.length, valid: v.valid, reports: reportFiles.length });
  } catch (e) {
    run.state.error = String(e);
    run.setStage("error");
    jsonl(run.logFile, { event: "run:error", error: String(e) });
    logErr(`run ${run.state.id} failed:`, e);
    await notifyMd(`*Run error* ${EMDASH} ${dom()}\n${mdEscape(String(e))}`);
  } finally {
    // Reap everything this run spawned (stage agents and the Xvfb/chrome/chromedriver they launch to
    // test the DOM), identified by a cwd inside the run dir, so nothing is left hanging after the run
    // ends, errors, or returns early. Runs on every exit path of this try. Best effort.
    try {
      const n = await killRunProcesses(run.dir);
      if (n) {
        log(`run ${run.state.id}: reaped ${n} leftover process(es)`);
        jsonl(run.logFile, { event: "run:reaped", processes: n });
      }
    } catch (e) {
      logErr(`run ${run.state.id}: reap failed:`, e);
    }
  }
}
