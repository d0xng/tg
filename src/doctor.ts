import { chrome, agents, telegram, RUNS_DIR } from "./config.ts";
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
  // The provider is read off the spec instead of asserted: this line printed "codex" literally, which was
  // already wrong whenever JS_MODEL named a claude id and became absurd once the miners moved to GLM.
  // "default" means no --effort flag is passed and the CLI's own default applies. Printing a level that
  // never reached a provider is how this output lied for the whole life of the pipeline.
  const eff = (e?: string) => e ?? "default (no flag)";
  console.log(`  js-analyzer   ${agents.jsAnalyzer.provider.padEnd(6)}  ${agents.jsAnalyzer.model}   effort=${eff(agents.jsAnalyzer.effort)}`);
  for (const h of agents.hunters) console.log(`  ${h.role.padEnd(13)} ${h.provider.padEnd(6)}  ${h.model}   effort=${eff(h.effort)}`);
  console.log(`  validator     ${agents.validator.provider}  ${agents.validator.model}   effort=${eff(agents.validator.effort)}`);
  console.log(`  reporter      ${agents.reporter.provider}  ${agents.reporter.model}   effort=${eff(agents.reporter.effort)}`);
  console.log(`  recon         ${agents.recon.provider}  ${agents.recon.model}   effort=${eff(agents.recon.effort)}`);

  console.log("\nio:");
  console.log(`  runs dir      ${RUNS_DIR}`);
  console.log(`  telegram      ${telegram.token ? "token set" : "NOT set (CLI-only mode)"} / chat ${telegram.chatId || "unset"}`);

  console.log("\nnote: only a spec that carries an effort sends the flag; the rest run at the CLI default.");
}

main();
