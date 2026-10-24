import { runReporter } from "./agents/reporter.ts";
import { runValidator } from "./agents/validator.ts";
import { owesWork, pendingWork, type Pending } from "./pending.ts";
import { log, warn } from "./log.ts";
import type { Run } from "./run.ts";

// The resume itself, as a function, because two callers drive it: the CLI (src/resume-run.ts) and the
// Telegram ingress, where the watchdog's "this run owes work" alert actually lands. Two copies of this
// logic would drift, and a drift between two readers of the same funnel is exactly how a payable finding
// got dropped once already.
//
// It does ONLY what is missing, leaning on the idempotence of the stages: the validator reuses a verdict
// already on disk, the reporter skips a report already written. It deliberately does not resume hunting,
// because runHunters has no skip guard and re-entering it would re-pay for every lead in the run.

export interface ResumeResult {
  /** Nothing is owed any more and nothing failed on this attempt. */
  ok: boolean;
  before: Pending;
  after: Pending;
  /** Agent invocations that produced no result during THIS attempt. */
  failures: string[];
  seconds: number;
  /** Set when there was nothing to do at all. */
  noop?: boolean;
}

export async function resumeRun(run: Run): Promise<ResumeResult> {
  const before = pendingWork(run.dir);
  const t0 = Date.now();
  const priorFailures = run.state.failures ?? [];

  if (!owesWork(before)) {
    // Everything is present, so whatever failed earlier has since been covered. Clear the record and let
    // the run read as finished instead of carrying a stale error forever.
    if (priorFailures.length || run.state.error) {
      run.state.failures = [];
      delete run.state.error;
      run.setStage("done");
      log("[resume] nothing pending; cleared stale failures and marked the run done");
    }
    return { ok: true, before, after: before, failures: [], seconds: 0, noop: true };
  }

  // Own the run while we work, so the watchdog sees a live owner instead of inferring death, and start
  // from a clean failure list: what matters afterwards is what failed on THIS attempt.
  run.claim();
  run.state.failures = [];
  run.save();

  if (before.needValidation.length) {
    const v = await runValidator(run);
    log(`[resume] validator -> ${v.valid} VALID, ${v.invalid} not-valid, ${v.failed} never ran, ${v.reused} reused`);
  }
  if (pendingWork(run.dir).needReport.length) {
    const n = await runReporter(run);
    log(`[resume] reporter -> ${n} report(s) in the run`);
  } else {
    log("[resume] no VALID finding is missing a report");
  }

  const after = pendingWork(run.dir);
  const failures = run.state.failures ?? [];
  const seconds = Math.round((Date.now() - t0) / 1000);
  const ok = !owesWork(after) && !failures.length;
  if (ok) {
    delete run.state.error;
    run.setStage("done");
    log(`[resume] complete in ${seconds}s: ${after.valid} VALID, all reported, run marked done`);
  } else {
    run.state.error =
      `resume: still owed ${after.needValidation.length} validation(s) and ${after.needReport.length} report(s)` +
      (failures.length ? `; ${failures.length} agent invocation(s) produced no result (${failures.join("; ")})` : "");
    run.setStage("error");
    warn(`[resume] incomplete in ${seconds}s: ${run.state.error}`);
  }
  return { ok, before, after, failures, seconds };
}

/** What a run owes, as lines for Telegram or the terminal. */
export function pendingLines(p: Pending, max = 12): string[] {
  const out: string[] = [];
  for (const f of p.needValidation.slice(0, max)) out.push(`  needs validation: ${f}`);
  if (p.needValidation.length > max) out.push(`  (+${p.needValidation.length - max} more to validate)`);
  for (const f of p.needReport.slice(0, max)) out.push(`  needs report    : ${f}`);
  if (p.needReport.length > max) out.push(`  (+${p.needReport.length - max} more to report)`);
  return out;
}

/** One block summarising a finished resume, for Telegram or the terminal. */
export function resumeSummary(run: Run, r: ResumeResult): string {
  if (r.noop) return `${run.state.domain}: nothing pending.`;
  const head = r.ok
    ? `${run.state.domain}: resume complete in ${r.seconds}s. ${r.after.valid} VALID, all reported, run marked done.`
    : `${run.state.domain}: resume INCOMPLETE in ${r.seconds}s.`;
  const lines = [head];
  if (!r.ok) {
    lines.push(`Still owed: ${r.after.needValidation.length} validation(s), ${r.after.needReport.length} report(s).`);
    if (r.failures.length) lines.push(...r.failures.map((f) => `- ${f}`));
  }
  return lines.join("\n");
}
