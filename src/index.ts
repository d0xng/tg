import { pollUpdates } from "./telegram.ts";
import { handleMessage } from "./agents/recon.ts";
import { log } from "./log.ts";

// Telegram-driven entry: long-poll messages and route each to the recon agent, which chats, settles a
// scope, expands wildcards (subfinder | httpx), and runs each host end to end through orchestrate(),
// reporting back to Telegram at every phase. One run at a time.
async function main() {
  log("huntline serve: Telegram recon ingress starting");
  await pollUpdates(handleMessage);
}

main();
