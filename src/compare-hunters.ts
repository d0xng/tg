import { readdirSync, readFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { agents } from "./config.ts";
import { runClaude, runCodex } from "./cli.ts";
import { log } from "./log.ts";

// Experiment: give ALL leads in a run to ALL 3 hunters at once (not round-robin), identical prompt,
// only the model differs. Run them in parallel, time each, and print who reaches a conclusion first
// and what each produced (so we can see if any model finds more). No extra steering from the operator.
//   bun run src/compare-hunters.ts <runDir-with-leads>
async function main() {
  const runDir = process.argv[2];
  if (!runDir) {
    console.error("usage: bun run src/compare-hunters.ts <runDir>");
    process.exit(1);
  }
  const leadsDir = join(runDir, "leads");
  const leadFiles = readdirSync(leadsDir).filter((f) => f.endsWith(".md"));
  const leadsBlob = leadFiles
    .map((f) => `----- lead: leads/${f} -----\n${readFileSync(join(leadsDir, f), "utf8")}`)
    .join("\n\n");
  const methodology = readFileSync(join(import.meta.dir, "..", "prompts", "hunter.md"), "utf8");
  const runState = JSON.parse(readFileSync(join(runDir, "run.json"), "utf8"));
  const scopeText = process.argv[3] || runState.scope; // real scope override (argv[3]) beats run.json
  log(`[compare] ${leadFiles.length} leads -> ${agents.hunters.length} hunters in parallel on ${runState.domain}`);

  // Identical for all three; only the model and the output dir name change.
  const buildPrompt = (role: string) =>
    [
      methodology,
      "",
      "----- THIS RUN -----",
      `Target domain: ${runState.domain}`,
      "Scope (authorized):",
      scopeText,
      "",
      `Work ALL of the leads below, in order. Write each confirmed finding as a markdown file in the directory findings-${role}/ (create it if needed). Do not write findings anywhere else.`,
      "",
      leadsBlob,
    ].join("\n");

  const t0 = Date.now();
  const results = await Promise.all(
    agents.hunters.map(async (spec) => {
      const start = Date.now();
      const outDir = join(runDir, `findings-${spec.role}`);
      mkdirSync(outDir, { recursive: true });
      const prompt = buildPrompt(spec.role);
      const res =
        spec.provider === "claude"
          ? await runClaude(spec, prompt, { cwd: runDir, addDirs: ["/opt/huntline/skills"], timeoutMs: 1_800_000 })
          : await runCodex(spec, prompt, {
              cwd: runDir,
              sandbox: "workspace-write",
              outFile: join(runDir, `compare-${spec.role}.last.txt`),
              timeoutMs: 1_800_000,
            });
      const durMs = Date.now() - start;
      const findings = existsSync(outDir) ? readdirSync(outDir).filter((f) => f.endsWith(".md")) : [];
      if (res.code !== 0 || findings.length === 0) {
        const tail = (res.stderr || res.stdout || "").trim().split("\n").slice(-6).join(" | ");
        log(`[compare] ${spec.role} note (exit ${res.code}): ${tail.slice(0, 500)}`);
      }
      log(
        `[compare] FINISHED ${spec.role} (${spec.model}) in ${(durMs / 1000).toFixed(0)}s at +${((Date.now() - t0) / 1000).toFixed(0)}s | exit ${res.code}${res.timedOut ? " TIMEOUT" : ""} | findings ${findings.length}`,
      );
      return { role: spec.role, model: spec.model, durMs, exit: res.code, timedOut: res.timedOut, findings };
    }),
  );

  const ranked = [...results].sort((a, b) => a.durMs - b.durMs);
  console.log("\n===== RACE (first to conclusion) =====");
  ranked.forEach((r, i) =>
    console.log(`${i + 1}. ${r.role} (${r.model}) — ${(r.durMs / 1000).toFixed(0)}s — ${r.findings.length} finding(s)${r.timedOut ? " [TIMED OUT]" : ""}`),
  );

  for (const r of results) {
    for (const f of r.findings) {
      console.log(`\n##### ${r.role} :: findings-${r.role}/${f} #####`);
      console.log(readFileSync(join(runDir, `findings-${r.role}`, f), "utf8"));
    }
  }
}
main();
