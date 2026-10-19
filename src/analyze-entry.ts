import { copyFileSync, readdirSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import { Run } from "./run.ts";
import { runJsAnalyzer } from "./agents/js-analyzer.ts";
import { log } from "./log.ts";

// Test harness: run ONLY the js-analyzer on a folder of JS, skipping the crawl. Lets us validate
// lead generation on a controlled set of files (e.g. one chunk) without a full run.
//   bun run src/analyze-entry.ts <jsSourceDir> [domain]
async function main() {
  const src = process.argv[2];
  const domain = process.argv[3] ?? "test.local";
  if (!src) {
    console.error("usage: bun run src/analyze-entry.ts <jsSourceDir> [domain]");
    process.exit(1);
  }
  const run = Run.create(domain, `analyze-only test from ${src}`);
  const jsDir = run.sub("js");
  const files = readdirSync(src).filter((f) => f.endsWith(".js") || f.endsWith(".map"));
  const manifest: Record<string, string> = {};
  for (const f of files) {
    copyFileSync(join(src, f), join(jsDir, f));
    manifest[f] = f;
  }
  writeFileSync(join(jsDir, "_manifest.json"), JSON.stringify(manifest, null, 2));
  run.state.counts.jsFiles = files.length;
  run.save();
  log(`analyze test: ${files.length} JS file(s) -> ${run.dir}`);

  const leads = await runJsAnalyzer(run);
  log(`js-analyzer wrote ${leads} lead(s) in ${run.sub("leads")}`);
  for (const lf of run.listMd("leads")) {
    console.log("\n===== leads/" + lf + " =====");
    console.log(readFileSync(join(run.sub("leads"), lf), "utf8"));
  }
}
main();
