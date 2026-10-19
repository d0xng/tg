import { Run } from "./run.ts";
import { runJsMiners } from "./agents/js-miners.ts";
import { log } from "./log.ts";

// Run ONLY the js-analyzer (lead generation) on an existing run's full corpus, and time it.
//   bun run src/analyze-run.ts <runId>
const id = process.argv[2];
if (!id) {
  console.error("usage: bun run src/analyze-run.ts <runId>");
  process.exit(1);
}
const run = Run.load(id);
log(`analyze-run: ${run.state.counts.jsFiles} js files in ${run.dir}`);
const t0 = Date.now();
const leads = await runJsMiners(run);
log(`analyze-run DONE: ${leads} leads in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
for (const lf of run.listMd("leads")) console.log("lead:", lf);
