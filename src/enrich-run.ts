import { Run } from "./run.ts";
import { enrichCorpus } from "./agents/js-enrich.ts";
import { log } from "./log.ts";

// Run ONLY the enrichment stage (reverse source maps + beautify) on an existing run's corpus.
//   bun run src/enrich-run.ts <runId>
const id = process.argv[2];
if (!id) {
  console.error("usage: bun run src/enrich-run.ts <runId>");
  process.exit(1);
}
const run = Run.load(id);
log(`enrich-run: ${run.dir}`);
const res = await enrichCorpus(run);
console.log(JSON.stringify(res, null, 2));
