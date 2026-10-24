import { readdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { agents, PROMPTS_DIR, timeouts, providerForModel, type AgentSpec } from "../config.ts";
import { agentFailure, failureSummary, runAgent, type CliResult } from "../cli.ts";
import { runLimited } from "../util/pool.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

// Sharded js-analysis: split the JS corpus into slices and run N miners IN PARALLEL, each a Codex
// reader that reads ONLY its slice (file by file, in full, never grep) and writes leads straight to
// leads/ the moment it finds a primitive. This is what makes 100% coverage of a big corpus feasible:
// one session cannot read hundreds of files, but many parallel miners each reading ~25 can.
//
// A miner that fails (codex exits non-zero: "Selected model is at capacity", the cyber classifier
// "flagged", a timeout) is RETRIED automatically on the next model in the chain, so a slice is never
// lost to one model's availability. Each attempt's stderr is captured for diagnosis.

function chunk<T>(a: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < a.length; i += n) out.push(a.slice(i, i + n));
  return out;
}

// Prefer the configured analyzer model, then fall back DOWN a chain that ends in a claude miner.
// gpt-5.6-sol -> gpt-6-sol covers model "at capacity" (model-specific). claude-opus-4-6 last covers
// the codex cyber classifier, which is CONTENT-triggered and so flags the lead on every GPT model;
// claude does not self-censor exploit analysis, so it reads the exploit-heavy slice a codex model
// cannot. Override the whole chain with MINER_MODEL_CHAIN (comma-separated). Each entry runs on the CLI its
// model id maps to (gpt-* -> codex, claude-* -> claude, glm-* -> GLM, deepseek-* -> DeepSeek; see runAgent).
function minerModelChain(): string[] {
  const env = process.env.MINER_MODEL_CHAIN;
  if (env) return env.split(",").map((s) => s.trim()).filter(Boolean);
  const ALLOWED = ["deepseek-flash", "gpt-5.6-sol", "gpt-6-sol", "claude-opus-4-6"];
  const first = agents.jsAnalyzer.model;
  return [first, ...ALLOWED.filter((m) => m !== first)];
}

export async function runJsMiners(
  run: Run,
  opts: { sliceSize?: number; concurrency?: number } = {},
): Promise<number> {
  const sliceSize = opts.sliceSize ?? Number(process.env.MINER_SLICE ?? 25);
  const concurrency = opts.concurrency ?? Number(process.env.MINER_CONCURRENCY ?? 5);
  const jsDir = run.sub("js");
  // Everything a corpus can legitimately contain, not just .js. The filter used to be /\.(m?js)$/
  // with a comment claiming ".map handled separately", and no such handling existed: a source map was
  // downloaded by the crawler and then never read by anybody. Now js-enrich reverses the maps, and a
  // third of what comes out of the maps on disk is TypeScript (measured: 129 .js, 61 .ts, 5 .tsx,
  // 1 .css), so the extensions have to be here or that code is recovered and then ignored.
  // SOURCES is the list; override it with MINER_EXTS (comma separated, no dots).
  // `map` is deliberately NOT here: js-enrich already pulls the original files out of every map that
  // carries sourcesContent, so handing a miner the raw .map as well is the same code twice in a
  // multi-megabyte JSON blob. For a map with no sourcesContent, js-enrich writes the sources[] list
  // as a small .json instead, which is the part worth reading: the app's own file tree.
  const exts = (process.env.MINER_EXTS ?? "js,mjs,cjs,ts,tsx,jsx,mts,cts,vue,svelte,html,htm,json")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const extRe = new RegExp(`\\.(${exts.map((e) => e.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})$`, "i");
  const files = readdirSync(jsDir).filter((f) => extRe.test(f) && f !== "_manifest.json" && f !== "_prune.json");
  const slices = chunk(files, sliceSize);
  const methodology = readFileSync(join(PROMPTS_DIR, "js-analyzer.md"), "utf8");
  const chain = minerModelChain();

  log(
    `[js-miners] ${files.length} files -> ${slices.length} miners x ~${sliceSize} files, ${concurrency} parallel; model chain: ${chain.join(" -> ")}`,
  );
  jsonl(run.logFile, { stage: "analyzing", event: "miners:start", files: files.length, miners: slices.length, concurrency, chain });
  const t0 = Date.now();

  const tasks = slices.map((slice, i) => async () => {
    const prompt = buildMinerPrompt(run, i, slice, methodology);
    let res: CliResult | null = null;
    let used = "";
    for (let a = 0; a < chain.length; a++) {
      const model = chain[a];
      const provider = providerForModel(model);
      const spec: AgentSpec = { ...agents.jsAnalyzer, provider, model };
      res = await runAgent(spec, prompt, {
        cwd: run.dir,
        addDirs: ["/opt/huntline/skills"],
        timeoutMs: timeouts.jsAnalyzerMs,
        outFile: join(run.sub("logs"), `miner-${i}.out.txt`), // codex only
      });
      used = model;
      writeFileSync(
        join(run.sub("logs"), `miner-${i}.${model}.log`),
        `exit=${res.code} timedOut=${res.timedOut}\n==STDERR (tail)==\n${(res.stderr ?? "").slice(-4000)}\n`,
      );
      if (res.code === 0 && !res.timedOut) break; // success -> stop retrying
      const next = a + 1 < chain.length ? chain[a + 1] : null;
      warn(
        `[js-miners] miner ${i} failed on ${model} (exit ${res.code}${res.timedOut ? " timeout" : ""})` +
          (next ? ` -> retry on ${next}` : " -> chain exhausted"),
      );
      jsonl(run.logFile, { stage: "analyzing", event: "miner:retry", miner: i, model, exit: res.code, timedOut: res.timedOut, next });
    }
    jsonl(run.logFile, { stage: "analyzing", event: "miner:done", miner: i, exit: res?.code ?? -1, model: used, files: slice.length });
    // Chain exhausted: this slice of the corpus was never read by anybody. It used to be a warn and
    // nothing else, so a run whose every miner ran out of quota still reported "0 leads" and finished
    // `done` -- a statement about the subscription dressed up as a statement about the target. Record it
    // so the orchestrator refuses to call the run clean and `analyze-run` can redo the slice later.
    const f = res ? agentFailure(res) : { reason: "no attempt", retryNow: false };
    if (f) {
      run.noteFailure(`${failureSummary(`miner ${i}`, f)} after ${chain.length} model(s), ${slice.length} file(s) unread`);
      warn(`[js-miners] miner ${i} exhausted model chain on ${f.reason} (${slice.length} files unread)`);
    }
  });
  await runLimited(tasks, concurrency);

  const leads = run.countLeads();
  run.state.counts.leads = leads;
  run.save();
  const secs = Math.round((Date.now() - t0) / 1000);
  log(`[js-miners] done: ${leads} leads in ${secs}s across ${slices.length} miners`);
  jsonl(run.logFile, { stage: "analyzing", event: "miners:all-done", leads, seconds: secs });
  return leads;
}

function buildMinerPrompt(run: Run, i: number, slice: string[], methodology: string): string {
  return [
    methodology,
    "",
    `----- YOU ARE MINER #${i} (one of several parallel miners) -----`,
    `Target: ${run.state.domain}`,
    "Scope (authorized):",
    run.state.scope,
    "",
    "Read ONLY the files in YOUR SLICE below, each one IN FULL (never grep). Other miners cover the",
    "rest of the corpus, so do not read files outside your slice. Read js/_manifest.json for the",
    "source URL of each artifact.",
    "",
    `The moment you find a primitive, WRITE a lead to leads/ named \`m${i}-<short-kebab-slug>.md\` (the`,
    `\`m${i}-\` prefix keeps your files from colliding with other miners), following the lead template`,
    "in the methodology. Do not fire anything at the target. Produce leads only.",
    "",
    `YOUR SLICE (${slice.length} files):`,
    ...slice.map((f) => "  js/" + f),
    "",
    `When done, print: miner #${i}, <N> leads written.`,
  ].join("\n");
}
