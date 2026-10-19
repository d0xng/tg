import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { agents, caps, PROMPTS_DIR, timeouts } from "../config.ts";
import { runClaude } from "../cli.ts";
import { runLimited } from "../util/pool.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

// The validator: a clean-session agent (no stake, did not find the bug) that re-runs each finding's
// PoC against the target itself, runs negative controls, and dictates a verdict + CVSS. Only findings
// it independently reproduces ship. This is the gate that kills false positives.
export async function runValidator(run: Run): Promise<{ valid: number; invalid: number; total: number }> {
  const findings = run.listMd("findings");
  if (!findings.length) {
    log("[validator] no findings to validate");
    return { valid: 0, invalid: 0, total: 0 };
  }
  const vdir = join(run.dir, "verdicts");
  mkdirSync(vdir, { recursive: true });
  const methodology = readFileSync(join(PROMPTS_DIR, "validator.md"), "utf8");
  const spec = agents.validator;
  log(`[validator] ${findings.length} findings in clean sessions (${spec.model})`);
  jsonl(run.logFile, { stage: "validating", event: "validator:start", findings: findings.length });

  const tasks = findings.map((f) => async () => {
    const base = f.replace(/\.md$/, "");
    const content = readFileSync(join(run.sub("findings"), f), "utf8");
    const prompt = [
      methodology,
      "",
      "----- THIS RUN -----",
      `Target domain: ${run.state.domain}`,
      "Scope (authorized):",
      run.state.scope,
      "",
      `Write your verdict to verdicts/${base}.md`,
      "",
      `----- CANDIDATE FINDING (findings/${f}) -----`,
      content,
    ].join("\n");
    try {
      const res = await runClaude(spec, prompt, { cwd: run.dir, addDirs: ["/opt/huntline/skills"], timeoutMs: timeouts.hunterMs });
      writeFileSync(
        join(run.sub("logs"), `validator-${f}.out.log`),
        `exit=${res.code} timedOut=${res.timedOut}\n==STDOUT==\n${res.stdout}\n==STDERR==\n${res.stderr}\n`,
      );
    } catch (e) {
      warn(`[validator] failed on ${f}: ${String(e)}`);
    }
    jsonl(run.logFile, { stage: "validating", event: "validator:done", finding: f });
  });
  await runLimited(tasks, caps.claudeConcurrency);

  let valid = 0;
  let invalid = 0;
  for (const f of findings) {
    const vf = join(vdir, f.replace(/\.md$/, "") + ".md");
    const v = existsSync(vf) ? readFileSync(vf, "utf8") : "";
    if (/VERDICT:\s*VALID/i.test(v)) valid++;
    else invalid++;
  }
  run.save();
  log(`[validator] done: ${valid} VALID, ${invalid} not-valid / ${findings.length}`);
  jsonl(run.logFile, { stage: "validating", event: "validator:all-done", valid, invalid, total: findings.length });
  return { valid, invalid, total: findings.length };
}
