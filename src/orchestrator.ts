import { readFileSync } from "fs";
import { join } from "path";
import { crawl } from "./agents/browser-operator.ts";
import { runJsMiners } from "./agents/js-miners.ts";
import { runHunters } from "./agents/hunter.ts";
import { runValidator } from "./agents/validator.ts";
import { runReporter } from "./agents/reporter.ts";
import { notifyMd, sendDocument, mdEscape } from "./telegram.ts";
import { jsonl, log, err as logErr } from "./log.ts";
import { timeouts } from "./config.ts";
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
      run.setStage("done");
      return;
    }

    // Stage 3 - hunters (exploit leads into candidate findings)
    run.setStage("hunting");
    await runHunters(run);
    const findingFiles = run.listMd("findings");
    if (!findingFiles.length) {
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
    const extra = v.skipped ? ` ${DOT} ${v.skipped} skipped (low/info)` : "";
    await notifyMd(
      `*Validation done* ${EMDASH} ${dom()}\n${mdEscape(`${v.valid} confirmed ${DOT} ${v.invalid} dropped${extra}`)}`,
    );
    if (v.valid === 0) {
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
    run.setStage("done");
    jsonl(run.logFile, { event: "run:done", findings: findingFiles.length, valid: v.valid, reports: reportFiles.length });
  } catch (e) {
    run.state.error = String(e);
    run.setStage("error");
    jsonl(run.logFile, { event: "run:error", error: String(e) });
    logErr(`run ${run.state.id} failed:`, e);
    await notifyMd(`*Run error* ${EMDASH} ${dom()}\n${mdEscape(String(e))}`);
  }
}
