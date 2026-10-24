import { findRuns, stopRun, stopSummary } from "./stop.ts";

// Stop a run from the terminal, by run id or by domain.
//   bun run src/stop-run.ts <runId|domain> [--all]
//
// The same thing is reachable from Telegram ("stop <id|domain>"), and both call stopRun() in src/stop.ts.
// By default it stops the newest match that is still running; --all stops every non-terminal match, which
// is what you want after firing the same domain several times.

const argv = process.argv.slice(2);
const all = argv.includes("--all");
const needle = argv.filter((a) => a !== "--all")[0];
if (!needle) {
  console.error("usage: bun run src/stop-run.ts <runId|domain> [--all]");
  process.exit(1);
}

const matches = findRuns(needle);
if (!matches.length) {
  console.error(`stop-run: nothing matches "${needle}"`);
  process.exit(1);
}
const live = matches.filter((m) => !m.terminal);
if (!live.length) {
  console.log(`stop-run: ${matches.length} run(s) match "${needle}" and all of them are already finished:`);
  for (const m of matches.slice(0, 8)) console.log(`  ${m.stage.padEnd(11)} ${m.id}`);
  process.exit(0);
}
const targets = all ? live : [live[0]];
if (live.length > 1 && !all) {
  console.log(`${live.length} runs are still going for "${needle}"; stopping the newest. Pass --all for every one:`);
  for (const m of live) console.log(`  ${m.stage.padEnd(11)} ${m.id}`);
}

for (const m of targets) {
  const r = await stopRun(m.id);
  console.log(stopSummary(r));
}
