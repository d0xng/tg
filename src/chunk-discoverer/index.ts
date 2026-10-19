// Chunk discoverer: given one JS bundle, statically enumerate the Webpack/Vite chunk URLs it can load
// WITHOUT navigating or executing the app. Webpack builds chunk URLs at runtime from an id->hash map
// plus a template (the full URL never appears as a literal), so a plain URL regex misses them; this
// parses the bundle, isolates the chunk-loading function, enumerates the ids, and runs that function
// in a sandbox (Sval) to compute each real URL. Prints one discovered value per line.
//
// The discoverer/fingerprinting/transformer logic is ported from jxscout (francisconeves97/jxscout,
// GPL) for d0x's internal huntline. Invoked as a bun subprocess by the browser-operator.
//   bun run src/chunk-discoverer/index.ts <js-file> <bruteforce-limit>
import * as fs from "fs";
import { discoverChunks } from "./discoverer";

function parseArgs(): { path: string; bruteForceLimit: number } {
  const [path, bruteForceLimitArg] = process.argv.slice(2);
  if (!path || !bruteForceLimitArg) {
    throw new Error("Both path and brute force limit arguments are required.");
  }
  const bruteForceLimit = parseInt(bruteForceLimitArg, 10);
  if (isNaN(bruteForceLimit)) {
    throw new Error("Brute force limit must be a valid number.");
  }
  return { path, bruteForceLimit };
}

try {
  const { path, bruteForceLimit } = parseArgs();
  const code = fs.readFileSync(path, "utf-8");
  const chunks = discoverChunks(code, bruteForceLimit);
  chunks.forEach((chunk) => console.log(chunk));
  process.exit(0);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
