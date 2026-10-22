import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "fs";
import { join } from "path";
import { jsonl, log, warn } from "../log.ts";
import { runLimited } from "../util/pool.ts";
import type { Run } from "../run.ts";

// Enrichment between the crawl and the miners. Two jobs, both aimed at the same thing: the miners
// read better code than the server shipped.
//
// 1. REVERSE SOURCE MAPS. The crawler has always downloaded .map files next to their bundle, and
//    nothing ever read them: the miner slice filter is /\.(m?js)$/ with a comment claiming ".map
//    handled separately", and no such handling existed. Measured on the corpora on disk: 63 target
//    source maps, 57 of them carrying full `sourcesContent`, 206 original files, 3.3 MB of
//    unminified source with real names (including TypeScript, e.g.
//    webpack://adn-frontend-library/./src/script/utils/banner-dimensions.ts, and component sources
//    like components/PromotionalCard/PromotionalCard.js). That is strictly better than any amount of
//    beautifying: beautified minified code is still single-letter identifiers.
//
// 2. BEAUTIFY WHAT IS LEFT. For bundles with no map, prettier turns one 5 MB line into readable code.
//    Measured cost on winchester: a 5.5 MB bundle takes 22 s and peaks at 1.37 GB RSS and doubles in
//    size, so this is capped by file size and run at low concurrency AFTER the crawl, when Chrome is
//    already gone. Two of those in parallel is how a 7.9 GB box gets OOM killed.
//
// Nothing is deleted and nothing is skipped silently. Every original byte stays: beautification keeps
// the server's exact response in js-raw/ before touching the file, because a report quotes bytes.
// JS_ENRICH=0 turns the whole stage off.

export type EnrichResult = {
  maps: { found: number; parsed: number; withContent: number; written: number; bytes: number; skippedEmpty: number; indexesWritten: number };
  beautify: {
    candidates: number;
    done: number;
    unchanged: number;
    skippedLarge: number;
    skippedFormatted: number;
    failed: number;
    bytesBefore: number;
    bytesAfter: number;
    /** How many files only parsed with a non-JavaScript parser, i.e. how much of the corpus is not JS. */
    byFallbackParser: Record<string, number>;
  };
  seconds: number;
};

const PRETTIER = process.env.PRETTIER_BIN ?? "/root/.npm-global/bin/prettier";

export async function enrichCorpus(run: Run): Promise<EnrichResult | null> {
  if (process.env.JS_ENRICH === "0") {
    log("[js-enrich] disabled by JS_ENRICH=0");
    return null;
  }
  const t0 = Date.now();
  const jsDir = run.sub("js");
  const res: EnrichResult = {
    maps: { found: 0, parsed: 0, withContent: 0, written: 0, bytes: 0, skippedEmpty: 0, indexesWritten: 0 },
    beautify: { candidates: 0, done: 0, unchanged: 0, skippedLarge: 0, skippedFormatted: 0, failed: 0, bytesBefore: 0, bytesAfter: 0, byFallbackParser: {} },
    seconds: 0,
  };

  reverseSourceMaps(jsDir, res);
  await beautify(jsDir, res);

  res.seconds = Math.round((Date.now() - t0) / 1000);
  log(
    `[js-enrich] source maps: ${res.maps.written} original files recovered from ${res.maps.withContent}/${res.maps.found} maps ` +
      `(${res.maps.indexesWritten} maps had no inlined source, their file list was written instead) ` +
      `(${(res.maps.bytes / 1048576).toFixed(1)} MB). beautified ${res.beautify.done}/${res.beautify.candidates} ` +
      `(${res.beautify.skippedLarge} too large, ${res.beautify.skippedFormatted} already readable, ${res.beautify.unchanged} unchanged, ${res.beautify.failed} failed` +
      `${Object.keys(res.beautify.byFallbackParser).length ? `; not JavaScript: ${JSON.stringify(res.beautify.byFallbackParser)}` : ""}). ${res.seconds}s`,
  );
  jsonl(run.logFile, { stage: "analyzing", event: "enrich:done", ...res });
  return res;
}

// ---------------------------------------------------------------------------- source maps

type SourceMap = { sources?: string[]; sourcesContent?: (string | null)[]; file?: string };

function reverseSourceMaps(jsDir: string, res: EnrichResult): void {
  let names: string[];
  try {
    names = readdirSync(jsDir).filter((f) => f.toLowerCase().endsWith(".map"));
  } catch {
    return;
  }
  res.maps.found = names.length;
  if (!names.length) return;

  const manPath = join(jsDir, "_manifest.json");
  let manifest: Record<string, string> = {};
  try {
    manifest = JSON.parse(readFileSync(manPath, "utf8"));
  } catch {
    /* a run with no manifest still gets the files */
  }
  const used = new Set(Object.values(manifest));
  try {
    for (const f of readdirSync(jsDir)) used.add(f);
  } catch {
    /* ignore */
  }

  for (const mapName of names) {
    let map: SourceMap;
    try {
      map = JSON.parse(readFileSync(join(jsDir, mapName), "utf8")) as SourceMap;
    } catch {
      continue; // not JSON, or truncated; the bundle itself is still there
    }
    res.maps.parsed++;
    const sources = map.sources ?? [];
    const contents = map.sourcesContent ?? [];
    if (!contents.some((c) => c && c.length)) {
      // No inlined source, but sources[] still names every original file the bundle was built from,
      // which is the app's own directory tree: route handlers, admin components, service modules.
      // Worth a miner's eyes, and tiny, unlike the multi-megabyte map it came from.
      if (sources.length) {
        const name = `${mapName}__sources.json`;
        try {
          writeFileSync(join(jsDir, name), JSON.stringify({ map: mapName, sources }, null, 2));
          manifest[`sourcemap-index://${mapName}`] = name;
          res.maps.indexesWritten++;
        } catch {
          /* ignore */
        }
      }
      continue;
    }
    res.maps.withContent++;

    for (let i = 0; i < sources.length; i++) {
      const body = contents[i];
      if (!body || !body.trim()) {
        res.maps.skippedEmpty++;
        continue;
      }
      const name = reversedName(mapName, sources[i] ?? `source-${i}`, used);
      try {
        writeFileSync(join(jsDir, name), body);
      } catch (e) {
        warn(`[js-enrich] could not write ${name}: ${(e as Error).message}`);
        continue;
      }
      // A pseudo-URL, not a real one: it records WHERE this file came from so a lead can cite the
      // map and the bundle it belongs to, and so nothing mistakes it for something fetched live.
      manifest[`sourcemap://${mapName}/${sources[i]}`] = name;
      res.maps.written++;
      res.maps.bytes += body.length;
    }
  }
  try {
    writeFileSync(manPath, JSON.stringify(manifest, null, 2));
  } catch (e) {
    warn(`[js-enrich] could not update the manifest: ${(e as Error).message}`);
  }
}

/**
 * `webpack://lib/./src/utils/thing.ts` under map `vendor.abc.js.map` becomes
 * `vendor.abc.js.map__lib_src_utils_thing.ts.js`. The map name is kept as a prefix because two
 * bundles routinely ship a source called `index.js`, and the trailing `.js` is appended so the
 * miner slice filter (/\.(m?js)$/) actually picks the file up: a `.ts` source otherwise never gets read.
 */
function reversedName(mapName: string, source: string, used: Set<string>): string {
  const clean = source
    .replace(/^webpack:\/\/\/?/, "")
    .replace(/^\.\//, "")
    .replace(/[^a-z0-9._/-]/gi, "_")
    .replace(/\/+/g, "_")
    .replace(/^_+/, "");
  let base = `${mapName}__${clean}`;
  // The real extension is kept now that the miner slice filter covers .ts/.tsx/.jsx/.vue/.html/.json.
  // It used to get a `.js` appended so the old /\.(m?js)$/ filter would pick the file up at all,
  // which worked but told the miner that a TypeScript file was JavaScript.
  if (!/\.[a-z0-9]{1,8}$/i.test(base)) base += ".js";
  base = base.slice(-180);
  let name = base;
  let i = 1;
  while (used.has(name)) {
    const m = base.match(/^(.*)(\.[a-z0-9]{1,8})$/i);
    name = m ? `${m[1]}.${i++}${m[2]}` : `${base}.${i++}`;
  }
  used.add(name);
  return name;
}

// ---------------------------------------------------------------------------- beautify

/**
 * The parsers to try, best guess first. A reversed source keeps its real extension before the `.js`
 * the stage appends (`apiContext.tsx.js`), so the name is a reliable signal for those; for everything
 * else the first non-space characters decide. Order matters: `html` must never be reached by a blind
 * fallback, because prettier's html parser accepts nearly any text and would rewrite a TypeScript
 * source as markup. Override the whole thing with JS_ENRICH_PARSERS.
 */
function parserChain(name: string, path: string): string[] {
  const env = process.env.JS_ENRICH_PARSERS;
  if (env) return env.split(",").map((s) => s.trim()).filter(Boolean);
  if (/\.(ts|tsx|mts|cts)$/i.test(name)) return ["typescript", "babel"];
  if (/\.(jsx|vue|svelte)$/i.test(name)) return ["babel", "typescript"];
  if (/\.(css|scss|less)$/i.test(name)) return ["css", "scss", "less"];
  if (/\.(html?|json)$/i.test(name)) return [/\.json$/i.test(name) ? "json" : "html"];
  let head = "";
  try {
    head = readFileSync(path, "utf8").slice(0, 4096).trimStart();
  } catch {
    return ["babel"];
  }
  if (/^<(!doctype|html|head|body|div|span|script)\b/i.test(head)) return ["html"];
  if (/^[[{]/.test(head)) return ["json", "babel"];
  return ["babel", "typescript", "json"];
}

/** Minified enough to be worth reformatting: one enormous line, or almost no line breaks. */
function looksMinified(head: string): boolean {
  const lines = head.split("\n");
  const max = lines.reduce((m, l) => Math.max(m, l.length), 0);
  const avg = head.length / Math.max(1, lines.length);
  return max > 1000 || avg > 200;
}

async function beautify(jsDir: string, res: EnrichResult): Promise<void> {
  if (!existsSync(PRETTIER)) {
    warn(`[js-enrich] prettier not found at ${PRETTIER}; skipping beautification`);
    return;
  }
  const maxBytes = Number(process.env.JS_ENRICH_BEAUTIFY_MAX_BYTES ?? 2_097_152);
  const concurrency = Number(process.env.JS_ENRICH_BEAUTIFY_CONCURRENCY ?? 2);
  const rawDir = join(jsDir, "..", "js-raw");

  // Same extensions the miners now read, so a recovered .ts that happens to be on one line still
  // gets formatted. The looksMinified gate below skips anything already readable, which is most of
  // what comes out of a source map.
  const BEAUTIFIABLE = /\.(m?js|cjs|ts|tsx|jsx|mts|cts|vue|svelte|html?|json|css|scss|less)$/i;
  let names: string[];
  try {
    names = readdirSync(jsDir).filter((f) => BEAUTIFIABLE.test(f) && !f.startsWith("_"));
  } catch {
    return;
  }

  const todo: { name: string; size: number }[] = [];
  for (const name of names) {
    const p = join(jsDir, name);
    let size = 0;
    try {
      size = statSync(p).size;
    } catch {
      continue;
    }
    if (!size) continue;
    let head: string;
    try {
      head = readFileSync(p, "utf8").slice(0, 65536);
    } catch {
      continue;
    }
    if (!looksMinified(head)) {
      res.beautify.skippedFormatted++;
      continue;
    }
    res.beautify.candidates++;
    if (size > maxBytes) {
      // A 5.5 MB bundle costs 22 s and 1.37 GB of RSS here. Left minified on purpose: the miners can
      // still read it, and OOM killing the box costs the whole run.
      res.beautify.skippedLarge++;
      continue;
    }
    todo.push({ name, size });
  }
  if (!todo.length) return;

  mkdirSync(rawDir, { recursive: true });
  const tasks = todo.map((t) => async () => {
    const p = join(jsDir, t.name);
    try {
      copyFileSync(p, join(rawDir, t.name)); // the server's exact bytes, for evidence
    } catch (e) {
      warn(`[js-enrich] could not preserve the original of ${t.name}: ${(e as Error).message}`);
      res.beautify.failed++;
      return;
    }
    // Not everything saved as .js is JavaScript, so pick the parser from what the file actually is
    // and only then fall back. Measured on one corpus: 7 of 9 babel failures were
    // `<script type="application/json">` blocks the crawler captures by textContent (JSON-LD, and a
    // Next.js __NEXT_DATA__ carrying props.pageProps and a channelId), and 2 were the SPA's
    // index.html served for a chunk URL that does not exist. Sniffing first matters because the
    // html parser accepts almost anything: reaching it by blind fallback would let it reformat a
    // TypeScript source as markup, and a third of the sources inside the maps on disk are .ts/.tsx.
    const parsers = parserChain(t.name, join(rawDir, t.name));
    // --ignore-path /dev/null is not optional. prettier 3 reads .gitignore by default, huntline's
    // .gitignore contains `runs/`, so every file in every corpus counted as ignored: prettier exited
    // 0, printed nothing, and changed not one byte. The stage reported 69 files beautified while the
    // corpus was untouched.
    let ok = false;
    for (const parser of parsers) {
      const proc = Bun.spawn(
        [PRETTIER, "--write", "--no-config", "--no-editorconfig", "--ignore-path", "/dev/null", "--log-level", "error", "--parser", parser, p],
        { stdout: "ignore", stderr: "pipe" },
      );
      const timer = setTimeout(() => {
        try {
          proc.kill();
        } catch {
          /* ignore */
        }
      }, Number(process.env.JS_ENRICH_BEAUTIFY_TIMEOUT_MS ?? 120_000));
      const code = await proc.exited;
      clearTimeout(timer);
      if (code === 0) {
        ok = true;
        if (parser !== "babel") res.beautify.byFallbackParser[parser] = (res.beautify.byFallbackParser[parser] ?? 0) + 1;
        break;
      }
      // prettier refuses what it cannot parse. Put the untouched original back before the next
      // attempt, so a half-written file never reaches a miner and the corpus never ends up worse
      // than it was before this stage ran.
      try {
        copyFileSync(join(rawDir, t.name), p);
      } catch {
        /* ignore */
      }
    }
    if (!ok) {
      res.beautify.failed++;
      return;
    }
    // Exit 0 is not proof of work: verify the file actually changed before counting it. That is what
    // caught the .gitignore problem above, where every run reported success over an untouched corpus.
    let after = 0;
    try {
      after = statSync(p).size;
    } catch {
      /* ignore */
    }
    if (after === t.size) {
      res.beautify.unchanged++;
      return;
    }
    res.beautify.bytesBefore += t.size;
    res.beautify.bytesAfter += after;
    res.beautify.done++;
  });
  await runLimited(tasks, concurrency);
}
