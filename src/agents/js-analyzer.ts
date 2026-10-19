import { join } from "path";
import { readFileSync, writeFileSync } from "fs";
import { agents, PROMPTS_DIR, timeouts } from "../config.ts";
import { runCodex } from "../cli.ts";
import { jsonl, log } from "../log.ts";
import type { Run } from "../run.ts";

// The js-analyzer: a GPT agent (Codex) that READS the collected JavaScript -- never greps -- to
// understand the app's logic and emit one lead per primitive. It writes leads straight to the run's
// leads/ directory. It does not fire anything at the target; a lead is a replicable document, not an
// exploit. The methodology is injected from prompts/js-analyzer.md because Codex does not auto-load
// .claude skills.

function buildPrompt(run: Run): string {
  const methodology = readFileSync(join(PROMPTS_DIR, "js-analyzer.md"), "utf8");
  return [
    methodology,
    "",
    "----- THIS RUN -----",
    `Target domain: ${run.state.domain}`,
    `Start URL: ${run.state.startUrl}`,
    "",
    "Scope (authorized):",
    run.state.scope,
    "",
    "Your workspace is the current working directory. Inside it:",
    "  js/      the collected JavaScript you must read (bundles, chunks, inline-*.js, *.map)",
    "  notes/   scratch observations",
    "  leads/   WRITE YOUR LEADS HERE, one markdown file per primitive",
    "",
    "Read js/_manifest.json first to see every artifact and its source URL. Then read the files.",
    "Write each lead as leads/<short-kebab-slug>.md following the lead template in the methodology.",
    "Do not fire any request at the target. Produce leads only. When done, print a one-line summary:",
    "the number of leads written and their classes.",
  ].join("\n");
}

export async function runJsAnalyzer(run: Run): Promise<number> {
  const prompt = buildPrompt(run);
  const outFile = join(run.sub("logs"), "js-analyzer.last.txt");
  log(`[js-analyzer] reading ${run.state.counts.jsFiles} JS artifacts with ${agents.jsAnalyzer.model}`);
  jsonl(run.logFile, { stage: "analyzing", event: "js-analyzer:start", jsFiles: run.state.counts.jsFiles });

  const res = await runCodex(agents.jsAnalyzer, prompt, {
    cwd: run.dir,
    sandbox: "workspace-write", // read js/, write leads/, no network
    outFile,
    timeoutMs: timeouts.jsAnalyzerMs,
  });

  writeFileSync(
    join(run.sub("logs"), "js-analyzer.out.log"),
    `exit=${res.code} timedOut=${res.timedOut}\n==STDOUT==\n${res.stdout}\n==STDERR==\n${res.stderr}\n`,
  );

  const leads = run.countLeads();
  run.state.counts.leads = leads;
  run.save();
  jsonl(run.logFile, {
    stage: "analyzing",
    event: "js-analyzer:done",
    exit: res.code,
    timedOut: res.timedOut,
    leads,
  });
  return leads;
}
