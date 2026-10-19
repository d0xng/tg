import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { Run } from "./run.ts";
import { runValidator } from "./agents/validator.ts";
import { log } from "./log.ts";

// Run ONLY the validator over an existing run's findings, and time it.
//   bun run src/validate-run.ts <runId> [scope]
const id = process.argv[2];
const scope = process.argv[3];
if (!id) {
  console.error("usage: bun run src/validate-run.ts <runId> [scope]");
  process.exit(1);
}
const run = Run.load(id);
if (scope) {
  run.state.scope = scope;
  run.save();
}
log(`validate-run: ${run.listMd("findings").length} findings in ${run.dir}`);
const t0 = Date.now();
const r = await runValidator(run);
log(`validate-run DONE in ${((Date.now() - t0) / 1000).toFixed(0)}s: ${r.valid} VALID / ${r.total}`);
for (const f of run.listMd("findings")) {
  const vf = join(run.dir, "verdicts", f.replace(/\.md$/, "") + ".md");
  const verdict = existsSync(vf) ? (readFileSync(vf, "utf8").match(/VERDICT:\s*([A-Za-z-]+)/i)?.[1] ?? "?") : "NO-VERDICT";
  console.log(`  ${verdict.padEnd(10)} ${f}`);
}
