import { pollUpdates } from "./telegram.ts";
import { Run } from "./run.ts";
import { orchestrate } from "./orchestrator.ts";
import { log } from "./log.ts";

// Telegram-driven entry: send the bot a domain + scope and it runs the pipeline, then pings back
// "N leads" and (Phase 2) "N findings + types". One run at a time for now.
async function main() {
  log("huntline serve: starting Telegram ingress");
  await pollUpdates(async (req) => {
    const run = Run.create(req.domain, req.scope);
    log(`run created from telegram: ${run.state.id}`);
    await orchestrate(run);
  });
}

main();
