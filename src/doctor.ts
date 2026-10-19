import { chrome, agents, telegram, codexEffortConfig, RUNS_DIR } from "./config.ts";
import { spawnCapture } from "./cli.ts";

// Environment sanity check. Verifies by EXECUTION, not by `command -v`: it actually runs each CLI.
async function check(name: string, cmd: string[]): Promise<void> {
  try {
    const r = await spawnCapture(cmd, { timeoutMs: 15_000 });
    const out = (r.stdout + r.stderr).trim().split("\n")[0] ?? "";
    console.log(`  ${r.code === 0 ? "ok " : "??"} ${name.padEnd(16)} ${out}`);
  } catch (e) {
    console.log(`  XX ${name.padEnd(16)} ${String(e)}`);
  }
}

async function main() {
  console.log("huntline doctor\n");
  console.log("runtime:");
  await check("bun", ["bun", "--version"]);
  await check("chrome", [chrome.bin, "--version"]);
  await check("codex", ["codex", "--version"]);
  await check("claude", ["claude", "--version"]);

  console.log("\nroster:");
  console.log(`  js-analyzer   codex   ${agents.jsAnalyzer.model}   effort=${agents.jsAnalyzer.effort}`);
  for (const h of agents.hunters) console.log(`  ${h.role.padEnd(13)} ${h.provider.padEnd(6)}  ${h.model}   effort=${h.effort}`);
  console.log(`  validator     ${agents.validator.provider}  ${agents.validator.model}`);
  console.log(`  reporter      ${agents.reporter.provider}  ${agents.reporter.model}`);
  console.log(`  codex effort config override: -c ${codexEffortConfig}`);

  console.log("\nio:");
  console.log(`  runs dir      ${RUNS_DIR}`);
  console.log(`  telegram      ${telegram.token ? "token set" : "NOT set (CLI-only mode)"} / chat ${telegram.chatId || "unset"}`);

  console.log("\nnote: codex reasoning-effort key/value ('" + codexEffortConfig + "') must be confirmed against this codex build.");
}

main();
