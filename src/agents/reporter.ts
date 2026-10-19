import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { agents, caps, PROMPTS_DIR, timeouts } from "../config.ts";
import { runClaude } from "../cli.ts";
import { runLimited } from "../util/pool.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

// The reporter: for each finding the validator marked VALID, write a submission ready report. It
// re-runs the PoC live before writing so every command reproduces, and it uses the validator's
// program priority and CVSS. First person, no em dashes.
export async function runReporter(run: Run): Promise<number> {
  const findings = run.listMd("findings");
  const vdir = join(run.dir, "verdicts");
  const valid = findings.filter((f) => {
    const vf = join(vdir, f.replace(/\.md$/, "") + ".md");
    return existsSync(vf) && /VERDICT:\s*VALID/i.test(readFileSync(vf, "utf8"));
  });
  if (!valid.length) {
    log("[reporter] no VALID findings to report");
    return 0;
  }
  const methodology = readFileSync(join(PROMPTS_DIR, "reporter.md"), "utf8");
  const spec = agents.reporter;
  log(`[reporter] ${valid.length} VALID findings -> reports (${spec.model})`);
  jsonl(run.logFile, { stage: "reporting", event: "reporter:start", findings: valid.length });

  const tasks = valid.map((f) => async () => {
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
      const res = await runClaude(spec, prompt, { cwd: run.dir, addDirs: ["/opt/huntline/skills"], timeoutMs: timeouts.hunterMs });
      writeFileSync(
        join(run.sub("logs"), `reporter-${f}.out.log`),
        `exit=${res.code} timedOut=${res.timedOut}\n==STDOUT==\n${res.stdout}\n==STDERR==\n${res.stderr}\n`,
      );
    } catch (e) {
      warn(`[reporter] failed on ${f}: ${String(e)}`);
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
