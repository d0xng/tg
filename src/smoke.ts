import { mkdtempSync, existsSync, readdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { crawl } from "./agents/browser-operator.ts";

// Dev smoke test for the browser-operator. Serves a tiny fixture on localhost and verifies Chrome +
// CDP capture every kind of JS: a static <script src>, a chunk injected by that script, a script
// injected later on a timer, a route-split chunk reached by following a same-origin link, inline
// scripts, and a source map. Spends ZERO subscription quota and touches nobody but 127.0.0.1.

const FILES: Record<string, { body: string; type: string }> = {
  "/": {
    type: "text/html",
    body: `<!doctype html><html><head>
<script src="/app.js"></script>
<script>
  window.__marker = "inline-script-marker-xyz";
  setTimeout(function(){ var e=document.createElement('script'); e.src='/late.js'; document.head.appendChild(e); }, 250);
</script>
</head><body><h1>fixture</h1><a href="/page2">go to page2</a></body></html>`,
  },
  "/app.js": {
    type: "application/javascript",
    body: `console.log("app");
var s = document.createElement('script'); s.src = '/chunk.js'; document.head.appendChild(s);
//# sourceMappingURL=/app.js.map
`,
  },
  "/chunk.js": { type: "application/javascript", body: `export const chunk = "dynamic-injected-chunk";` },
  "/late.js": { type: "application/javascript", body: `window.__late = "timer-injected";` },
  "/page2": {
    type: "text/html",
    body: `<!doctype html><html><head><script src="/route-chunk.js"></script></head><body>page2</body></html>`,
  },
  "/route-chunk.js": { type: "application/javascript", body: `window.__route = "route-split-chunk";` },
  "/app.js.map": { type: "application/json", body: `{"version":3,"sources":["app.ts"],"mappings":""}` },
};

const server = Bun.serve({
  port: 0,
  fetch(req) {
    const path = new URL(req.url).pathname;
    const f = FILES[path];
    if (!f) return new Response("not found", { status: 404 });
    return new Response(f.body, { headers: { "content-type": f.type } });
  },
});

const base = `http://127.0.0.1:${server.port}`;
const jsDir = join(mkdtempSync(join(tmpdir(), "huntline-smoke-")), "js");
console.log(`smoke: serving fixture at ${base}, capturing into ${jsDir}\n`);

try {
  const { jsFiles, manifest } = await crawl(base, jsDir, {
    idleNoNewJsMs: 3000,
    maxMs: 30_000,
    maxPages: 20,
    idleMs: 500,
    idleMaxWaitMs: 4000,
  });

  const names = existsSync(jsDir) ? readdirSync(jsDir) : [];
  const urls = Object.keys(manifest);
  const want = ["/app.js", "/chunk.js", "/late.js", "/route-chunk.js"];
  const gotStatic = want.filter((w) => urls.some((u) => u.endsWith(w)));
  const gotInline = Object.keys(manifest).some((k) => k.startsWith("inline#"));
  const gotMap = names.some((n) => n.endsWith(".map"));

  console.log("captured urls:");
  for (const u of urls) console.log("   " + u + "  ->  " + manifest[u]);
  console.log("\nfiles on disk:", names.join(", "));
  console.log("\nresults:");
  console.log(`  js artifacts captured : ${jsFiles}`);
  console.log(`  static scripts        : ${gotStatic.length}/${want.length}  (${gotStatic.join(", ")})`);
  console.log(`  inline script         : ${gotInline ? "yes" : "no"}`);
  console.log(`  source map            : ${gotMap ? "yes" : "no"}`);

  const ok = gotStatic.length === want.length && gotInline && gotMap;
  console.log(`\nSMOKE ${ok ? "PASS" : "FAIL"}`);
  process.exitCode = ok ? 0 : 1;
} finally {
  server.stop(true);
}
