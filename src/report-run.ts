import { Run } from "./run.ts";
import { runReporter } from "./agents/reporter.ts";
import { log } from "./log.ts";

// Run ONLY the reporter over an existing run's VALID findings, and time it.
//   bun run src/report-run.ts <runId> [scope]
const id = process.argv[2];
const scope = process.argv[3];
if (!id) {
  console.error("usage: bun run src/report-run.ts <runId> [scope]");
  process.exit(1);
}
const run = Run.load(id);
if (scope) {
  run.state.scope = scope;
  run.save();
}
log(`report-run on ${run.dir}`);
const t0 = Date.now();
const n = await runReporter(run);
log(`report-run DONE in ${((Date.now() - t0) / 1000).toFixed(0)}s: ${n} reports`);
for (const r of run.listMd("reports")) console.log("report:", r);
