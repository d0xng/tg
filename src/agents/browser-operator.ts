import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { chrome } from "../config.ts";
import { log, warn } from "../log.ts";

// The browser-operator: launches headless Chrome, navigates the target UNAUTHENTICATED, triggers SPA
// routes and lazy chunk loads, and captures EVERY piece of JavaScript the page pulls -- static
// bundles, dynamically injected chunks, inline scripts -- plus source maps. It never logs in and
// never submits data; it clicks and navigates to make the app reveal its code, then saves it to
// disk for the js-analyzer. Chrome is driven directly over CDP (no puppeteer/playwright dep), which
// matches the existing headless-CDP approach and runs anywhere Chrome does, including the VPS.

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface CrawlOpts {
  idleNoNewJsMs?: number; // stop after this long with NO newly saved on-target artifact (default 60000)
  maxMs?: number; // hard safety ceiling so the crawl cannot run forever (default 3600000 = 60min)
  maxPages?: number; // safety cap on distinct pages visited (default 20000)
  idleMs?: number; // quiet period that counts as "network idle"
  idleMaxWaitMs?: number; // cap on how long we wait for idle per page
}

class CDP {
  private ws: WebSocket;
  private id = 0;
  private pending = new Map<number, { res: (v: any) => void; rej: (e: any) => void }>();
  private handlers = new Map<string, ((p: any) => void)[]>();

  constructor(url: string) {
    this.ws = new WebSocket(url);
  }
  open(): Promise<void> {
    return new Promise((res, rej) => {
      this.ws.onopen = () => res();
      this.ws.onerror = (e) => rej(new Error("CDP ws error: " + String((e as any)?.message ?? e)));
      this.ws.onmessage = (m) => this.onMessage(m);
    });
  }
  private onMessage(m: MessageEvent): void {
    let d: any;
    try {
      d = JSON.parse(typeof m.data === "string" ? m.data : "");
    } catch {
      return;
    }
    if (d.id !== undefined) {
      const p = this.pending.get(d.id);
      if (p) {
        this.pending.delete(d.id);
        d.error ? p.rej(new Error(JSON.stringify(d.error))) : p.res(d.result);
      }
    } else if (d.method) {
      for (const h of this.handlers.get(d.method) ?? []) h(d.params);
    }
  }
  send<T = any>(method: string, params: Record<string, unknown> = {}, timeoutMs = 30000): Promise<T> {
    const id = ++this.id;
    return new Promise<T>((res, rej) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) rej(new Error("CDP timeout: " + method));
      }, timeoutMs);
      this.pending.set(id, {
        res: (v) => { clearTimeout(timer); res(v); },
        rej: (e) => { clearTimeout(timer); rej(e); },
      });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  on(method: string, h: (p: any) => void): void {
    const a = this.handlers.get(method) ?? [];
    a.push(h);
    this.handlers.set(method, a);
  }
  close(): void {
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
  }
}

function isJs(url: string, mime: string): boolean {
  const u = url.split("?")[0];
  return /javascript|ecmascript/i.test(mime) || /\.(m?js)$/i.test(u);
}

// Analytics / ad / tracker hosts. Their JS is skip-list for bug bounty anyway, AND their per-request
// variants (unique query strings on every page) would otherwise be saved as "new" files and keep
// resetting the no-new-JS timer, so the crawl could never quiesce. We neither capture nor count
// them. Extend with the CRAWL_DENY_HOSTS env var (comma-separated).
const DENY_HOSTS = [
  "googletagmanager.com", "google-analytics.com", "googlesyndication.com", "googleadservices.com",
  "doubleclick.net", "facebook.net", "facebook.com", "linkedin.com", "licdn.com", "ads-twitter.com",
  "t.co", "snapchat.com", "sc-static.net", "hotjar.com", "clarity.ms", "mixpanel.com", "segment.com",
  "segment.io", "amplitude.com", "fullstory.com", "heapanalytics.com", "onetrust.com", "cookielaw.org",
  "bing.com", "branch.io", "quantserve.com", "scorecardresearch.com", "adroll.com", "criteo.com",
  "taboola.com", "outbrain.com", "yandex.ru",
  ...(process.env.CRAWL_DENY_HOSTS ?? "").split(",").map((s) => s.trim()).filter(Boolean),
];
function isDeniedHost(url: string): boolean {
  let h: string;
  try {
    h = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return DENY_HOSTS.some((d) => h === d || h.endsWith("." + d));
}

// Inline analytics / consent bootstraps (GTM, gtag, Facebook/Snap/Twitter/LinkedIn pixels, OneTrust).
// Skipped so the corpus stays app code + app data; every OTHER inline (Next.js data payloads, window
// config, bootstrap JSON) is kept because it can carry endpoints, ids, config, tokens, or PII.
const ANALYTICS_INLINE =
  /googletagmanager\.com|google-analytics\.com|gtag\(|dataLayer\.push|fbq\(|connect\.facebook\.net|fbevents|snaptr\(|tr\.snapchat\.com|twq\(|static\.ads-twitter\.com|snap\.licdn\.com|_linkedin_partner_id|lintrk\(|hotjar|clarity\.ms|window\.clarity|OneTrust|Optanon|cookielaw\.org|mixpanel|cdn\.segment\.com|amplitude\.com/i;
function isAnalyticsInline(code: string): boolean {
  return ANALYTICS_INLINE.test(code);
}

function fileNameFor(url: string, used: Set<string>): string {
  let base: string;
  try {
    const u = new URL(url);
    base = (u.hostname + u.pathname).replace(/[^a-z0-9.-]/gi, "_");
  } catch {
    base = url.replace(/[^a-z0-9.-]/gi, "_");
  }
  if (!/\.(m?js)$/i.test(base)) base += ".js";
  base = base.slice(-180);
  let name = base;
  let i = 1;
  while (used.has(name)) name = base.replace(/\.(m?js)$/i, `.${i++}.js`);
  used.add(name);
  return name;
}

async function launchChrome(): Promise<{ proc: Bun.Subprocess; port: number; profile: string }> {
  const port = 9222 + Math.floor(Math.random() * 2000);
  const profile = join(import.meta.dir, "..", "..", `.chrome-${port}`);
  mkdirSync(profile, { recursive: true });
  const proc = Bun.spawn(
    [
      chrome.bin,
      "--headless=new",
      `--remote-debugging-port=${port}`,
      "--remote-allow-origins=*", // required for CDP websocket on modern Chrome
      "--no-sandbox",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--disable-background-networking",
      "--no-first-run",
      "--no-default-browser-check",
      "--user-data-dir=" + profile,
      "about:blank",
    ],
    { stdout: "ignore", stderr: "ignore" },
  );
  return { proc, port, profile };
}

async function pageWebSocket(port: number): Promise<string> {
  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json`);
      const list = (await res.json()) as any[];
      const page = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      /* chrome not up yet */
    }
    await delay(200);
  }
  throw new Error("chrome devtools endpoint never came up");
}

export async function crawl(
  startUrl: string,
  jsDir: string,
  opts: CrawlOpts = {},
): Promise<{ jsFiles: number; manifest: Record<string, string> }> {
  const maxMs = opts.maxMs ?? 3_600_000;
  const maxPages = opts.maxPages ?? 20000;
  const idleNoNewJsMs = opts.idleNoNewJsMs ?? 60_000;
  const idleMs = opts.idleMs ?? 1200;
  const idleMaxWaitMs = opts.idleMaxWaitMs ?? 8000;
  const hardDeadline = Date.now() + maxMs;

  mkdirSync(jsDir, { recursive: true });
  const origin = new URL(startUrl).origin;
  const targetHost = new URL(startUrl).hostname.toLowerCase();
  const baseDomain = targetHost.split(".").slice(-2).join(".");
  const allowHosts = (process.env.CRAWL_ALLOW_HOSTS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  // Capture JS only from the target's own domain (+ subdomains, + allowlisted CDNs). Third-party JS on
  // other domains (widgets, libs, trackers) is off-target noise and dropped.
  const onTarget = (u: string): boolean => {
    try {
      const h = new URL(u).hostname.toLowerCase();
      return h === targetHost || h === baseDomain || h.endsWith("." + baseDomain) || allowHosts.some((a) => h === a || h.endsWith("." + a));
    } catch {
      return false;
    }
  };

  const { proc, port, profile } = await launchChrome();
  let cdp: CDP | null = null;
  const manifest: Record<string, string> = {};
  const usedNames = new Set<string>();
  const savedUrls = new Set<string>();
  const saves: Promise<void>[] = [];
  const respMeta = new Map<string, { url: string; mime: string }>();
  let inflight = 0;
  let lastActivity = Date.now();
  let lastNewJs = Date.now(); // reset only when a NEW on-target artifact is saved; drives the stop
  const markNewJs = () => {
    lastNewJs = Date.now();
  };

  const waitIdle = async (): Promise<void> => {
    const cap = Date.now() + idleMaxWaitMs;
    while (Date.now() < cap && Date.now() < hardDeadline) {
      if (inflight <= 0 && Date.now() - lastActivity > idleMs) return;
      await delay(150);
    }
  };

  let pages = 0;
  try {
    const wsUrl = await pageWebSocket(port);
    cdp = new CDP(wsUrl);
    await cdp.open();

    await cdp.send("Network.enable");
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");

    cdp.on("Network.requestWillBeSent", () => {
      inflight++;
      lastActivity = Date.now();
    });
    const done = () => {
      inflight--;
      lastActivity = Date.now();
    };
    cdp.on("Network.loadingFailed", done);
    cdp.on("Network.responseReceived", (p: any) => {
      respMeta.set(p.requestId, { url: p.response.url, mime: p.response.mimeType ?? "" });
    });
    cdp.on("Network.loadingFinished", (p: any) => {
      done();
      const meta = respMeta.get(p.requestId);
      if (meta && isJs(meta.url, meta.mime) && !savedUrls.has(meta.url) && onTarget(meta.url) && !isDeniedHost(meta.url)) {
        savedUrls.add(meta.url);
        markNewJs();
        saves.push(saveBody(cdp!, p.requestId, meta.url, jsDir, usedNames, manifest));
      }
    });

    // Inline scripts live on the current document, so capture them per page (the DOM is replaced on
    // every route navigation). Dedup across pages by content; a new inline also counts as new JS.
    let inlineIdx = 0;
    const seenInline = new Set<string>();
    const captureInline = async (): Promise<void> => {
      try {
        const r = await cdp!.send<any>("Runtime.evaluate", {
          expression:
            "JSON.stringify([...document.querySelectorAll('script:not([src])')].map(s=>s.textContent).filter(t=>t&&t.trim().length>16))",
          returnByValue: true,
        });
        const inline = JSON.parse(r.result?.value ?? "[]") as string[];
        for (const code of inline) {
          if (isAnalyticsInline(code)) continue; // skip GTM/gtag/fbq/consent bootstraps; keep app data
          const key = code.length + ":" + code.slice(0, 64);
          if (seenInline.has(key)) continue;
          seenInline.add(key);
          const name = `inline-${inlineIdx++}.js`;
          writeFileSync(join(jsDir, name), code);
          manifest[`inline#${inlineIdx - 1}`] = name;
          markNewJs();
        }
      } catch {
        /* best effort */
      }
    };

    // Same-origin link frontier. Keep discovering links, clicking everything, and navigating; stop
    // ONLY when no new JS has appeared for idleNoNewJsMs (or the safety ceiling / page cap is hit).
    const visited = new Set<string>();
    const queued = new Set<string>();
    const frontier: string[] = [];
    const enqueue = (u: string): void => {
      let n: URL;
      try {
        n = new URL(u);
      } catch {
        return;
      }
      if (n.origin !== origin) return; // stay on the target origin
      n.hash = "";
      const s = n.href;
      if (visited.has(s) || queued.has(s)) return;
      queued.add(s);
      frontier.push(s);
    };
    const collectLinks = async (): Promise<void> => {
      try {
        const r = await cdp!.send<any>("Runtime.evaluate", {
          expression:
            "JSON.stringify([...new Set([...document.querySelectorAll('a[href]')].map(a=>a.href))])",
          returnByValue: true,
        });
        for (const h of JSON.parse(r.result?.value ?? "[]") as string[]) enqueue(h);
      } catch {
        /* best effort */
      }
    };
    const clickAll = async (): Promise<void> => {
      try {
        await cdp!.send("Runtime.evaluate", {
          expression:
            "(()=>{let n=0;document.querySelectorAll('button,[role=button],[onclick],[data-toggle],[data-bs-toggle]').forEach(b=>{try{b.click();n++;}catch(e){}});return n;})()",
          timeout: 4000,
        });
      } catch {
        /* best effort */
      }
    };

    enqueue(startUrl);
    while (true) {
      if (Date.now() - lastNewJs > idleNoNewJsMs) break; // no new on-target artifact for the idle window
      if (Date.now() > hardDeadline) break; // safety ceiling
      if (pages >= maxPages) break;
      const url = frontier.shift();
      if (!url) {
        if (inflight <= 0) break; // nothing queued and nothing loading -> done
        await delay(250);
        continue;
      }
      if (visited.has(url)) continue;
      visited.add(url);
      pages++;
      log(`[browser-operator] (${pages}) ${url}`);
      try {
        await cdp.send("Page.navigate", { url });
        await waitIdle();
        await clickAll();
        await waitIdle();
        await captureInline();
        await collectLinks();
      } catch {
        /* a bad page must not stop the crawl */
      }
    }

    await Promise.allSettled(saves);
  } finally {
    cdp?.close();
    try {
      proc.kill();
    } catch {
      /* ignore */
    }
    try {
      rmSync(profile, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }

  writeFileSync(join(jsDir, "_manifest.json"), JSON.stringify(manifest, null, 2));
  const jsFiles = Object.keys(manifest).length;
  log(`[browser-operator] captured ${jsFiles} JS artifacts from ${pages} pages -> ${jsDir}`);
  return { jsFiles, manifest };
}

async function saveBody(
  cdp: CDP,
  requestId: string,
  url: string,
  jsDir: string,
  usedNames: Set<string>,
  manifest: Record<string, string>,
): Promise<void> {
  try {
    const { body, base64Encoded } = await cdp.send<any>("Network.getResponseBody", { requestId });
    const buf = base64Encoded ? Buffer.from(body, "base64") : Buffer.from(body, "utf8");
    const name = fileNameFor(url, usedNames);
    writeFileSync(join(jsDir, name), buf);
    manifest[url] = name;
    await maybeSaveSourceMap(url, buf.toString("utf8"), jsDir, name);
  } catch {
    /* body may be gone after a route change; acceptable */
  }
}

// Source maps are usually only fetched by devtools, so grab them directly (best effort, read-only).
async function maybeSaveSourceMap(jsUrl: string, text: string, jsDir: string, jsName: string): Promise<void> {
  const m = text.slice(-4000).match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/);
  if (!m) return;
  const ref = m[1];
  if (ref.startsWith("data:")) return;
  try {
    const mapUrl = new URL(ref, jsUrl).href;
    const res = await fetch(mapUrl);
    if (!res.ok) return;
    writeFileSync(join(jsDir, jsName + ".map"), await res.text());
  } catch {
    /* ignore */
  }
}
