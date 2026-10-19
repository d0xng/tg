import { Run } from "./run.ts";
import { runHunters } from "./agents/hunter.ts";
import { log } from "./log.ts";

// Run ONLY the hunter stage over an existing run's leads, and time it.
//   bun run src/hunt-run.ts <runId> [scope]
const id = process.argv[2];
const scope = process.argv[3];
if (!id) {
  console.error("usage: bun run src/hunt-run.ts <runId> [scope]");
  process.exit(1);
}
const run = Run.load(id);
if (scope) {
  run.state.scope = scope;
  run.save();
}
log(`hunt-run: ${run.listMd("leads").length} leads in ${run.dir}`);
const t0 = Date.now();
const findings = await runHunters(run);
log(`hunt-run DONE: ${findings} findings in ${((Date.now() - t0) / 1000).toFixed(0)}s -> ${JSON.stringify(run.state.findingsByType)}`);
for (const f of run.listMd("findings")) console.log("finding:", f);
