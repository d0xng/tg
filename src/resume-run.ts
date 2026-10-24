import { Run } from "./run.ts";
import { owesWork, pendingWork } from "./pending.ts";
import { pendingLines, resumeRun, resumeSummary } from "./resume.ts";
import { log } from "./log.ts";

// Finish a run that was cut short, doing ONLY what is missing.
//   bun run src/resume-run.ts <runId> [--dry-run] [scope...]
//
// The same work is reachable from Telegram ("resume <runId>"), which is where the watchdog's alert lands;
// both call resumeRun() in src/resume.ts so neither can drift from the other. Safe to run repeatedly:
// the validator reuses a verdict already on disk and the reporter skips a report already written, so it
// pays only for what is absent. It does NOT resume hunting; use src/hunt-run.ts for that, knowing it
// re-pays for every lead.

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
  // A clean line instead of a stack trace: the id is almost always a paste, and a typo in it is the most
  // likely way this command is called wrong.
  console.error(`resume-run: no run called "${id}" (expected ${id}/run.json under the runs directory)`);
  process.exit(1);
}
if (scope) {
  run.state.scope = scope;
  run.save();
}

const p = pendingWork(run.dir);
log(
  `resume-run ${id}: ${p.total} finding(s), ${p.needValidation.length} to validate, ` +
    `${p.needReport.length} VALID without a report`,
);
for (const line of pendingLines(p)) console.log(line);
for (const f of run.state.failures ?? []) console.log(`  prior failure   : ${f}`);

if (dry) {
  console.log(owesWork(p) ? "\n(dry run, nothing spent)" : "\nnothing pending");
  process.exit(0);
}

const r = await resumeRun(run);
console.log("\n" + resumeSummary(run, r));
process.exit(r.ok ? 0 : 1);
