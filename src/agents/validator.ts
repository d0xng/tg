import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { agents, caps, PROMPTS_DIR, timeouts } from "../config.ts";
import { failureSummary, runAgentChecked } from "../cli.ts";
import { runLimited } from "../util/pool.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

export interface ValidationResult {
  valid: number;
  invalid: number;
  skipped: number;
  total: number;
  /**
   * Invocations that never produced a result (429 session limit, provider overload, timeout). These are
   * NOT verdicts: the finding is still undecided and is worth re-running. Kept out of `invalid` on
   * purpose, because conflating the two is what wrote off six uber.com candidates as false positives.
   */
  failed: number;
  /** Already carried a complete verdict from an earlier pass, so this run did not pay for it again. */
  reused: number;
}

// Severity gate: the validator is an expensive clean-session re-verification, so we do NOT spend it on
// low/info findings -- except open redirect, the one low class worth reporting. By the time a finding
// exists the hunter has already PROVEN impact, so its `severity:` is reliable (not a guess). We fail
// OPEN: a finding with a missing/ambiguous severity is validated anyway, so a mislabel never silently
// drops a real bug. Skipped findings stay on disk with a SKIPPED verdict; the reporter only ships VALID.
function severityOf(content: string): string {
  const m = content.match(/^\s*severity:\s*["']?([a-z]+)/im);
  return m ? m[1].toLowerCase() : "";
}
function isOpenRedirect(file: string, content: string): boolean {
  return (
    /redirect/i.test(file) ||
    /open[-\s]?redirect/i.test(content) ||
    /^\s*class:\s*[^\n]*redirect/im.test(content)
  );
}
/**
 * The verdict a file DECLARES: the first `VERDICT:` token in it, uppercased. Testing the whole file
 * once per outcome is wrong, and real data proves it: one saudiacargo verdict is VALID while its body
 * carries "VERDICT:" at the end of a line and "SKIPPED" at the start of the next, and JS `\s*` crosses
 * the newline (grep, being line based, does not), so a SKIPPED test matched a VALID verdict and silently
 * dropped a payable finding from the count. The reporter uses this too, so both stages always agree on
 * which findings are VALID.
 */
export function verdictOf(content: string): string {
  return (content.match(/VERDICT:\s*([A-Za-z-]+)/i)?.[1] ?? "").toUpperCase();
}

const DECIDED = new Set(["VALID", "INVALID", "NEEDS-FIX", "SKIPPED"]);

function shouldValidate(file: string, content: string): boolean {
  const sev = severityOf(content);
  if (sev === "medium" || sev === "high" || sev === "critical") return true;
  if (isOpenRedirect(file, content)) return true; // the only low that pays
  if (sev === "low" || sev === "info" || sev === "informational") return false;
  return true; // unknown / ambiguous severity -> fail open (never silently drop)
}

// The validator: a clean-session agent (no stake, did not find the bug) that re-runs each finding's
// PoC against the target itself, runs negative controls, and dictates a verdict + CVSS. Only findings
// it independently reproduces ship. This is the gate that kills false positives.
export async function runValidator(run: Run): Promise<ValidationResult> {
  const findings = run.listMd("findings");
  if (!findings.length) {
    log("[validator] no findings to validate");
    return { valid: 0, invalid: 0, skipped: 0, total: 0 };
  }
  const vdir = join(run.dir, "verdicts");
  mkdirSync(vdir, { recursive: true });
  const methodology = readFileSync(join(PROMPTS_DIR, "validator.md"), "utf8");
  const spec = agents.validator;

  // Severity gate: validate only medium+ (or open redirect); skip low/info to save budget.
  const toValidate: string[] = [];
  let skipped = 0;
  let reused = 0;
  for (const f of findings) {
    // Already decided by an earlier pass. A run cut short by the watchdog or by a session limit is
    // re-entered with `bun run src/validate-run.ts <runId>`, and that must not pay ~$1.8 per finding for
    // verdicts that are already on disk. Only a COMPLETE verdict counts; a half-written file is redone.
    const existing = join(vdir, f.replace(/\.md$/, "") + ".md");
    if (existsSync(existing) && DECIDED.has(verdictOf(readFileSync(existing, "utf8")))) {
      reused++;
      continue;
    }
    const content = readFileSync(join(run.sub("findings"), f), "utf8");
    if (shouldValidate(f, content)) {
      toValidate.push(f);
    } else {
      skipped++;
      const base = f.replace(/\.md$/, "");
      writeFileSync(
        join(vdir, base + ".md"),
        `VERDICT: SKIPPED\nreason: low/info severity (not open-redirect), gated out of validation to save budget\nseverity: ${severityOf(content) || "unknown"}\n`,
      );
      jsonl(run.logFile, { stage: "validating", event: "validator:skipped", finding: f, severity: severityOf(content) });
    }
  }

  log(
    `[validator] ${toValidate.length} to validate, ${skipped} skipped (low/info), ${reused} already decided, of ${findings.length} (${spec.model})`,
  );
  jsonl(run.logFile, { stage: "validating", event: "validator:start", toValidate: toValidate.length, skipped, reused });

  // Findings whose validator never ran. Their verdict is unknown, not negative.
  const failedFiles = new Set<string>();
  const tasks = toValidate.map((f) => async () => {
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
      const { res, failure } = await runAgentChecked(spec, prompt, {
        cwd: run.dir,
        addDirs: ["/opt/huntline/skills"],
        timeoutMs: timeouts.hunterMs,
      });
      writeFileSync(
        join(run.sub("logs"), `validator-${f}.out.log`),
        `exit=${res.code} timedOut=${res.timedOut}\n==STDOUT==\n${res.stdout}\n==STDERR==\n${res.stderr}\n`,
      );
      if (failure) {
        // The agent never ran, so it said nothing about this finding. Record that and leave the finding
        // undecided instead of letting a missing verdict file read as "false positive".
        failedFiles.add(f);
        run.noteFailure(failureSummary(spec.role, failure));
        jsonl(run.logFile, { stage: "validating", event: "validator:failed", finding: f, reason: failure.reason, detail: failure.detail });
        return;
      }
    } catch (e) {
      failedFiles.add(f);
      run.noteFailure(`${spec.role}: ${String(e)}`);
      warn(`[validator] failed on ${f}: ${String(e)}`);
      jsonl(run.logFile, { stage: "validating", event: "validator:failed", finding: f, reason: String(e) });
      return;
    }
    jsonl(run.logFile, { stage: "validating", event: "validator:done", finding: f });
  });
  await runLimited(tasks, caps.claudeConcurrency);

  // Tally over EVERY finding, not just the ones this pass validated, so a re-entered run reports the
  // whole picture (the orchestrator's "valid === 0 -> done" decision depends on it). Findings whose
  // validator never produced a result are excluded entirely: they are undecided, not rejected.
  let valid = 0;
  let invalid = 0;
  for (const f of findings) {
    if (failedFiles.has(f)) continue;
    const vf = join(vdir, f.replace(/\.md$/, "") + ".md");
    const vd = verdictOf(existsSync(vf) ? readFileSync(vf, "utf8") : "");
    if (vd === "SKIPPED") continue; // severity-gated, counted in `skipped`
    if (vd === "VALID") valid++;
    else invalid++;
  }
  const failed = failedFiles.size;
  run.save();
  log(
    `[validator] done: ${valid} VALID, ${invalid} not-valid, ${skipped} skipped, ${failed} NEVER RAN / ${findings.length}`,
  );
  jsonl(run.logFile, { stage: "validating", event: "validator:all-done", valid, invalid, skipped, failed, reused, total: findings.length });
  return { valid, invalid, skipped, failed, reused, total: findings.length };
}
