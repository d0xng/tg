import { Run } from "./run.ts";
import { orchestrate } from "./orchestrator.ts";
import { log } from "./log.ts";

// Manual kickoff, no Telegram needed:
//   bun run hunt <domain|url> [--crawl-only] [scope words...]
// Everything after the target that is not a flag is kept as the scope text.
async function main() {
  const argv = process.argv.slice(2);
  const crawlOnly = argv.includes("--crawl-only");
  const rest = argv.filter((a) => a !== "--crawl-only");
  const target = rest[0];
  if (!target) {
    console.error("usage: bun run hunt <domain|url> [--crawl-only] [scope...]");
    process.exit(1);
  }
  const scope = rest.slice(1).join(" ") || `authorized target: ${target}`;
  const run = Run.create(target, scope);
  log(`run created: ${run.state.id}  (${run.dir})`);
  await orchestrate(run, { crawlOnly });
  log(`run ${run.state.id} finished: stage=${run.state.stage} leads=${run.state.counts.leads}`);
}

main();
