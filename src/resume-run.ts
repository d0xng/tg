import { Run } from "./run.ts";
import { runValidator } from "./agents/validator.ts";
import { runReporter } from "./agents/reporter.ts";
import { owesWork, pendingWork } from "./pending.ts";
import { log, warn } from "./log.ts";

// Finish a run that was cut short, doing ONLY what is missing.
//   bun run src/resume-run.ts <runId> [--dry-run] [scope...]
//
// This is the companion to the stage failures recorded in run.json: a 429 session limit leaves findings
// unvalidated and VALID findings unreported, and running the whole pipeline again would re-crawl, re-mine
// and re-hunt everything. Both stages it drives are idempotent (the validator reuses a verdict already on
// disk, the reporter skips a report already written), so this is safe to run as many times as needed and
// pays only for what is actually absent.
//
// It deliberately does NOT resume the hunting stage: runHunters has no skip guard, so re-entering it
// would re-pay for every lead in the run. Use `bun run src/hunt-run.ts <runId>` if that is what you want,
// knowing the cost.
//
// --dry-run prints what is owed and exits without spending anything.

const argv = process.argv.slice(2);
const dry = argv.includes("--dry-run");
const rest = argv.filter((a) => a !== "--dry-run");
const id = rest[0];
const scope = rest.slice(1).join(" ");
if (!id) {
  console.error("usage: bun run src/resume-run.ts <runId> [--dry-run] [scope...]");
  process.exit(1);
}

let run: Run;
try {
  run = Run.load(id);
} catch {
  // A clean line instead of a stack trace: the id is almost always a paste, and a typo in it is the
  // most likely way this command is called wrong.
  console.error(`resume-run: no run called "${id}" (expected ${id}/run.json under the runs directory)`);
  process.exit(1);
}
if (scope) {
  run.state.scope = scope;
  run.save();
}

const before = pendingWork(run.dir);
log(
  `resume-run ${id}: ${before.total} finding(s), ${before.needValidation.length} to validate, ` +
    `${before.needReport.length} VALID without a report`,
);
for (const f of before.needValidation) console.log("  needs validation:", f);
for (const f of before.needReport) console.log("  needs report    :", f);
const priorFailures = run.state.failures ?? [];
if (priorFailures.length) for (const f of priorFailures) console.log("  prior failure   :", f);

if (dry) {
  console.log(owesWork(before) ? "\n(dry run, nothing spent)" : "\nnothing pending");
  process.exit(0);
}
if (!owesWork(before)) {
  log("resume-run: nothing pending");
  if (priorFailures.length) {
    // The work is all present, so whatever failed earlier has since been covered. Clear the record and
    // let the run read as finished instead of carrying a stale error forever.
    run.state.failures = [];
    delete run.state.error;
    run.setStage("done");
    log("resume-run: cleared stale failures, run marked done");
  }
  process.exit(0);
}

// Own the run while we work, so the watchdog sees a live owner rather than inferring death, and start
// from a clean failure list: what matters afterwards is what failed on THIS attempt.
run.claim();
run.state.failures = [];
run.save();

const t0 = Date.now();
if (before.needValidation.length) {
  const v = await runValidator(run);
  log(`resume-run: validator -> ${v.valid} VALID, ${v.invalid} not-valid, ${v.failed} never ran, ${v.reused} reused`);
}
const mid = pendingWork(run.dir);
if (mid.needReport.length) {
  const n = await runReporter(run);
  log(`resume-run: reporter -> ${n} report(s) in the run`);
} else {
  log("resume-run: no VALID finding is missing a report");
}

const after = pendingWork(run.dir);
const failures = run.state.failures ?? [];
const secs = ((Date.now() - t0) / 1000).toFixed(0);
if (!owesWork(after) && !failures.length) {
  delete run.state.error;
  run.setStage("done");
  log(`resume-run DONE in ${secs}s: run complete, marked done (${after.valid} VALID, all reported)`);
} else {
  run.state.error =
    `resume-run: still owed ${after.needValidation.length} validation(s) and ${after.needReport.length} report(s)` +
    (failures.length ? `; ${failures.length} agent invocation(s) produced no result (${failures.join("; ")})` : "");
  run.setStage("error");
  warn(`resume-run INCOMPLETE in ${secs}s: ${run.state.error}`);
  for (const f of after.needValidation) console.log("  still needs validation:", f);
  for (const f of after.needReport) console.log("  still needs report    :", f);
}
