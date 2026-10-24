import { Run } from "./run.ts";
import { orchestrate } from "./orchestrator.ts";
import { expandTargets, isWildcard } from "./recon/expand.ts";
import { log } from "./log.ts";

// Manual kickoff, no Telegram needed:
//   bun run hunt <domain|url|*.wildcard> [--crawl-only] [scope words...]
//
// A wildcard is expanded with subfinder | httpx and every live host is hunted in turn, which the Telegram
// path could always do and the terminal could not. The scope text stays the ORIGINAL argument for every
// host, because `*.example.com` is the authorization boundary and that is what the agents need to read,
// not the single host they happen to be working.
async function main() {
  const argv = process.argv.slice(2);
  const crawlOnly = argv.includes("--crawl-only");
  const rest = argv.filter((a) => a !== "--crawl-only");
  const target = rest[0];
  if (!target) {
    console.error("usage: bun run hunt <domain|url|*.wildcard> [--crawl-only] [scope...]");
    process.exit(1);
  }
  const scope = rest.slice(1).join(" ") || `authorized target: ${target}`;

  const hosts = await expandTargets([target], (m) => log(`[recon] ${m}`));
  if (!hosts.length) {
    console.error(
      isWildcard(target)
        ? `no live host came out of "${target}"`
        : `could not make a target out of "${target}"`,
    );
    process.exit(1);
  }
  if (hosts.length > 1) log(`${hosts.length} host(s) to hunt from ${target}`);

  let i = 0;
  for (const url of hosts) {
    i++;
    if (hosts.length > 1) log(`host ${i}/${hosts.length}: ${url}`);
    const run = Run.create(url, scope);
    log(`run created: ${run.state.id}  (${run.dir})`);
    try {
      await orchestrate(run, { crawlOnly });
    } catch (e) {
      // orchestrate already records and reports its own failures; one bad host must not abandon the rest.
      log(`run ${run.state.id} threw: ${String(e)}`);
    }
    log(`run ${run.state.id} finished: stage=${run.state.stage} leads=${run.state.counts.leads}`);
  }
}

main();
