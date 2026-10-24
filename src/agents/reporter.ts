import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { agents, caps, PROMPTS_DIR, timeouts } from "../config.ts";
import { failureSummary, runAgentChecked } from "../cli.ts";
import { verdictOf } from "../util/verdict.ts";
import { stopRequested } from "../util/stopflag.ts";
import { runLimited } from "../util/pool.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

// The reporter: for each finding the validator marked VALID, write a submission ready report. It
// re-runs the PoC live before writing so every command reproduces, and it uses the validator's
// program priority and CVSS. First person, no em dashes.
export async function runReporter(run: Run): Promise<number> {
  const findings = run.listMd("findings");
  const vdir = join(run.dir, "verdicts");
  // Same verdict reader the validator uses, so the two stages can never disagree about which findings
  // are VALID (a whole-file regex here would have been one more place for the cross-line trap).
  const valid = findings.filter((f) => {
    const vf = join(vdir, f.replace(/\.md$/, "") + ".md");
    return existsSync(vf) && verdictOf(readFileSync(vf, "utf8")) === "VALID";
  });
  if (!valid.length) {
    log("[reporter] no VALID findings to report");
    return 0;
  }
  // A report already on disk is not written twice. This is what makes `bun run src/report-run.ts <runId>`
  // cheap on a run whose reporting stage was cut short: it picks up exactly what is missing.
  const todo = valid.filter((f) => !existsSync(join(run.sub("reports"), f.replace(/\.md$/, "") + ".md")));
  const reused = valid.length - todo.length;
  if (!todo.length) {
    log(`[reporter] all ${valid.length} VALID findings already have a report`);
    return run.listMd("reports").length;
  }
  const methodology = readFileSync(join(PROMPTS_DIR, "reporter.md"), "utf8");
  const spec = agents.reporter;
  log(`[reporter] ${todo.length} VALID findings -> reports (${reused} already written) (${spec.model})`);
  jsonl(run.logFile, { stage: "reporting", event: "reporter:start", findings: todo.length, reused });

  const tasks = todo.map((f) => async () => {
    if (stopRequested(run.dir)) return; // stop requested: do not start another report
    const base = f.replace(/\.md$/, "");
    const finding = readFileSync(join(run.sub("findings"), f), "utf8");
    const verdict = readFileSync(join(vdir, base + ".md"), "utf8");
    const prompt = [
      methodology,
      "",
      "----- THIS RUN -----",
      `Target domain: ${run.state.domain}`,
      "Scope (authorized):",
      run.state.scope,
      "",
      `Write your report to reports/${base}.md`,
      "",
      `----- CONFIRMED FINDING (findings/${f}) -----`,
      finding,
      "",
      "----- VALIDATOR VERDICT (use its program priority and CVSS) -----",
      verdict,
    ].join("\n");
    try {
      const { res, failure } = await runAgentChecked(spec, prompt, {
        cwd: run.dir,
        addDirs: ["/opt/huntline/skills"],
        timeoutMs: timeouts.hunterMs,
      });
      writeFileSync(
        join(run.sub("logs"), `reporter-${f}.out.log`),
        `exit=${res.code} timedOut=${res.timedOut}\n==STDOUT==\n${res.stdout}\n==STDERR==\n${res.stderr}\n`,
      );
      if (failure) {
        // No report for a VALID finding because the agent never ran. The finding keeps its VALID
        // verdict, so re-running this stage later writes the report that is missing.
        run.noteFailure(failureSummary(spec.role, failure));
        jsonl(run.logFile, { stage: "reporting", event: "reporter:failed", finding: f, reason: failure.reason, detail: failure.detail });
        return;
      }
    } catch (e) {
      run.noteFailure(`${spec.role}: ${String(e)}`);
      warn(`[reporter] failed on ${f}: ${String(e)}`);
      jsonl(run.logFile, { stage: "reporting", event: "reporter:failed", finding: f, reason: String(e) });
      return;
    }
    jsonl(run.logFile, { stage: "reporting", event: "reporter:done", finding: f });
  });
  await runLimited(tasks, caps.claudeConcurrency);

  const reports = run.listMd("reports").length;
  run.save();
  log(`[reporter] done: ${reports} reports in ${run.sub("reports")}`);
  jsonl(run.logFile, { stage: "reporting", event: "reporter:all-done", reports });
  return reports;
}
