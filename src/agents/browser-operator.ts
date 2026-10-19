import { mkdirSync, writeFileSync, readFileSync, rmSync } from "fs";
import { join } from "path";
import { chrome } from "../config.ts";
import { log, warn } from "../log.ts";
import { runLimited } from "../util/pool.ts";

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
      "--ignore-certificate-errors", // proceed past TLS cert mismatches (CNAME/SNI/Akamai) instead of stopping on Chrome's interstitial, so the actual site loads and its JS is captured
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

  // Frontier scope = the start host PLUS any same-registrable-domain host we LAND on by following a
  // redirect (HTTP or JS). So rdex.verisk.com -> gateway-login.verisk.com (the SSO) is followed and
  // crawled; a footer link to a sibling marketing site is NOT crawled unless a redirect took us there;
  // a redirect to a third-party IdP (a different registrable domain) is never added. JS capture stays
  // registrable-domain (onTarget), so a dependency chunk hosted on a sibling subdomain is still saved
  // even when we do not crawl that subdomain's pages.
  const scopeHosts = new Set<string>([targetHost, ...allowHosts]);
  const sameRegDomain = (h: string): boolean => h === baseDomain || h.endsWith("." + baseDomain);
  const inScopeHost = (h: string): boolean =>
    scopeHosts.has(h) || allowHosts.some((a) => h === a || h.endsWith("." + a));
  const noteLanding = (u: string): void => {
    try {
      const h = new URL(u).hostname.toLowerCase();
      if (sameRegDomain(h)) scopeHosts.add(h);
    } catch {
      /* ignore */
    }
  };

  const { proc, port, profile } = await launchChrome();
  let cdp: CDP | null = null;
  const manifest: Record<string, string> = {};
  const usedNames = new Set<string>();
  const savedUrls = new Set<string>();
  const saves: Promise<void>[] = [];
  let pendingSaves = 0; // bodies still being fetched + harvested; the loop must not quit while > 0
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
    // Proceed past TLS cert errors at the protocol level too: the --ignore-certificate-errors launch
    // flag is unreliable in headless=new, so a hostname/CNAME cert mismatch (common behind Akamai) can
    // still strand the main frame on Chrome's interstitial. This makes the site load and its JS capture.
    try {
      await cdp.send("Security.setIgnoreCertificateErrors", { ignore: true });
    } catch {
      /* older Chrome without this command: the launch flag covers it */
    }

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
        pendingSaves++;
        saves.push(
          saveBody(cdp!, p.requestId, meta.url, jsDir, usedNames, manifest, harvestUrls).finally(() => {
            pendingSaves--;
          }),
        );
        // A same-registrable-domain subdomain we pull first-party JS from is part of the app (e.g. an
        // SSO embedded as a widget/micro-frontend, not a top-level redirect). Bring it into scope: that
        // seeds its root AND releases any routes already harvested for it from other bundles.
        try {
          const h = new URL(meta.url).hostname.toLowerCase();
          if (sameRegDomain(h)) addScopeHost(h);
        } catch {
          /* ignore */
        }
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

    // Same-DOMAIN link frontier: the target's registrable domain and ALL its subdomains are in scope,
    // so a redirect to a sibling subdomain (e.g. an SSO host like gateway-login.verisk.com) is followed
    // and its pages are crawled, not merely captured. Keep discovering links, clicking everything, and
    // navigating; stop ONLY when no new JS has appeared for idleNoNewJsMs (or the safety ceiling / page
    // cap is hit).
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
      if (n.protocol !== "http:" && n.protocol !== "https:") return; // only navigable web pages
      if (!inScopeHost(n.hostname.toLowerCase())) return; // frontier = start host + same-domain redirect targets, NOT every linked sibling subdomain
      n.hash = "";
      const s = n.href;
      if (visited.has(s) || queued.has(s)) return;
      queued.add(s);
      frontier.push(s);
    };
    // A URL harvested from JS is only worth WALKING once its host proves to be part of the app: i.e. we
    // actually load first-party JS from it (addScopeHost) or a redirect lands us on it. Same-domain URLs
    // for hosts not yet proven in-scope wait in pendingHarvest, so a route referenced in rdex's bundle
    // BEFORE gateway-login is known still gets walked once gateway-login enters scope (no ordering race),
    // while marketing hosts that merely appear as strings and whose code we never load are never walked.
    const pendingHarvest = new Set<string>();
    const drainPending = (): void => {
      for (const u of [...pendingHarvest]) {
        try {
          if (inScopeHost(new URL(u).hostname.toLowerCase())) {
            pendingHarvest.delete(u);
            enqueue(u);
          }
        } catch {
          pendingHarvest.delete(u);
        }
      }
    };
    const addScopeHost = (h: string): void => {
      if (scopeHosts.has(h)) return;
      scopeHosts.add(h);
      enqueue(`https://${h}/`); // seed its root
      drainPending(); // release routes already harvested for this host
    };
    // Routes that only live as string literals inside JS (SPA router configs) never appear as <a href>,
    // so harvest absolute same-domain URLs from every captured bundle. This is how the SSO's real pages
    // (e.g. /app/dcp/auth/login, /app/isonet/reset-password/request) get walked: they are strings in the
    // bundles, not links on the page. GET-only; assets and APIs are skipped.
    const ASSET_EXT = /\.(m?js|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|json|mp4|webm|avif|wasm|pdf|xml|txt)(\?|#|$)/i;
    const harvestUrls = (text: string): void => {
      const found = text.match(/https?:\/\/[a-zA-Z0-9.\-]+(?::\d+)?(?:\/[^\s"'`<>()\\{}|]*)?/g);
      if (!found) return;
      let seen = 0;
      for (const raw of found) {
        if (seen > 400) break;
        const u = raw.replace(/[.,);:]+$/, "");
        if (ASSET_EXT.test(u) || /\/(api|graphql)\b|\/v\d+\//i.test(u)) continue;
        try {
          const h = new URL(u).hostname.toLowerCase();
          if (!sameRegDomain(h)) continue; // only the target's own registrable domain
          seen++;
          if (inScopeHost(h)) enqueue(u); // host already proven in-scope -> walk it now
          else pendingHarvest.add(u); // wait until we load first-party JS from this host (or get redirected there)
        } catch {
          /* ignore */
        }
      }
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
    const currentUrl = async (): Promise<string> => {
      try {
        const r = await cdp!.send<any>("Runtime.evaluate", { expression: "location.href", returnByValue: true });
        return r.result?.value ?? "";
      } catch {
        return "";
      }
    };
    // Click EVERYTHING interactive, not just <button>. React/Angular/Vue bind clicks with
    // addEventListener (no onclick attribute), so besides the obvious interactive selectors we also
    // treat any element whose computed cursor is "pointer" as clickable. Each click can open a menu or
    // lazy-load a route chunk, which the network layer then captures -- every button unlocks more JS.
    // Guards keep it non-destructive: we never click real form-submit controls (so no data is
    // submitted), never click a real <a href> (those are walked through the frontier, not clicked, so a
    // click never navigates us off the page), and never open a new tab.
    const clickAll = async (): Promise<void> => {
      try {
        await cdp!.send("Runtime.evaluate", {
          expression: `(()=>{
            const set=new Set([...document.querySelectorAll('button,[role=button],[role=menuitem],[role=tab],[role=link],[role=switch],[onclick],[data-toggle],[data-bs-toggle],[routerlink],[ng-click],summary,details,[tabindex]')]);
            for(const el of document.querySelectorAll('a,button,div,span,li,i,svg,img,p,label,td,th,[class],[role]')){try{if(getComputedStyle(el).cursor==='pointer')set.add(el);}catch(e){}}
            let n=0;
            for(const el of set){try{
              const tag=el.tagName;
              const type=((el.getAttribute&&el.getAttribute('type'))||'').toLowerCase();
              if(type==='submit'||type==='image'||el.type==='submit')continue;   // never submit data
              if(tag==='A'&&el.getAttribute('href'))continue;                    // real links go through the frontier, not clicks
              if(el.target==='_blank')continue;                                  // never open external tabs
              el.click();n++;
            }catch(e){}}
            return n;
          })()`,
          timeout: 8000,
        });
      } catch {
        /* best effort */
      }
    };

    // --- Webpack/Vite chunk pre-fetching -------------------------------------------------------------
    // Enumerate the chunk URLs the app CAN lazy-load straight from the runtime bundle and fetch them,
    // even if no navigation or click ever triggered them. Webpack builds those URLs at runtime from an
    // id->hash map + a template, so they never appear as string literals and harvestUrls cannot see
    // them; the discoverer subprocess parses the bundle and computes them. This closes the biggest JS
    // coverage gap (lazy route / admin bundles). Fetched out-of-band (not via the browser), rate-limited.
    const CHUNK_DISCOVERER = join(import.meta.dir, "..", "chunk-discoverer", "index.ts");
    const bruteforceLimit = Number(process.env.CRAWL_CHUNK_BRUTEFORCE ?? 3000);
    const chunkConc = Number(process.env.CRAWL_CHUNK_CONCURRENCY ?? 4);
    const chunkDelayMs = Number(process.env.CRAWL_CHUNK_DELAY_MS ?? 150);
    const runDiscoverer = async (filePath: string): Promise<string[]> => {
      try {
        const proc = Bun.spawn([process.execPath, "run", CHUNK_DISCOVERER, filePath, String(bruteforceLimit)], {
          stdout: "pipe",
          stderr: "ignore",
        });
        const out = await new Response(proc.stdout).text();
        await proc.exited;
        return out.split("\n").map((s) => s.trim()).filter(Boolean);
      } catch {
        return [];
      }
    };
    // A discovered value may be absolute, root-relative, or publicPath-relative (e.g. "static/chunks/x.js").
    // Resolve it to concrete URLs; the 200-or-skip check at fetch time discards wrong guesses.
    const resolveChunk = (value: string, sourceUrl: string): string[] => {
      const out = new Set<string>();
      const v = value.trim();
      if (!v || v.includes("undefined")) return [];
      if (/^https?:\/\//i.test(v)) { out.add(v); return [...out]; }
      try { out.add(new URL(v, sourceUrl).href); } catch { /* ignore */ }
      try { if (v.startsWith("/")) out.add(new URL(v, new URL(sourceUrl).origin).href); } catch { /* ignore */ }
      const seg = v.replace(/^\//, "").split("/")[0];
      if (seg) {
        for (const ku of Object.keys(manifest)) {
          if (!/^https?:/i.test(ku)) continue;
          const i = ku.indexOf("/" + seg + "/");
          if (i !== -1) { out.add(ku.slice(0, i + 1) + v.replace(/^\//, "")); break; }
        }
      }
      return [...out];
    };
    const fetchAndSaveChunk = async (url: string): Promise<boolean> => {
      if (savedUrls.has(url) || !onTarget(url) || isDeniedHost(url)) return false;
      try {
        const res = await fetch(url, { tls: { rejectUnauthorized: false }, redirect: "follow" } as any);
        if (!res.ok) return false;
        const ct = res.headers.get("content-type") ?? "";
        const text = await res.text();
        if (!isJs(url, ct) && /^\s*<(!doctype|html)/i.test(text)) return false; // wrong resolution landed on an HTML page
        savedUrls.add(url);
        const name = fileNameFor(url, usedNames);
        writeFileSync(join(jsDir, name), text);
        manifest[url] = name;
        harvestUrls(text); // a fetched chunk can itself reference more routes/chunks
        await maybeSaveSourceMap(url, text, jsDir, name);
        return true;
      } catch {
        return false;
      }
    };
    const prefetchChunks = async (): Promise<void> => {
      let total = 0;
      for (let round = 0; round < 2; round++) {
        const candidates = new Set<string>();
        for (const [u, f] of Object.entries(manifest)) {
          if (!/^https?:/i.test(u)) continue; // skip inline
          let body = "";
          try { body = readFileSync(join(jsDir, f), "utf8"); } catch { continue; }
          if (!/Loading chunk |__vite__mapDeps/.test(body)) continue; // only runtime/entry bundles carry the chunk map
          for (const val of await runDiscoverer(join(jsDir, f))) {
            for (const abs of resolveChunk(val, u)) candidates.add(abs);
          }
        }
        const todo = [...candidates].filter((u) => !savedUrls.has(u) && onTarget(u) && !isDeniedHost(u));
        if (!todo.length) break;
        let roundNew = 0;
        const tasks = todo.map((u) => async () => {
          if (await fetchAndSaveChunk(u)) roundNew++;
          await delay(chunkDelayMs);
        });
        await runLimited(tasks, chunkConc);
        total += roundNew;
        if (!roundNew) break; // nothing new this round -> stable
      }
      if (total) log(`[browser-operator] chunk pre-fetch: +${total} lazy chunks not reached by navigation`);
    };

    enqueue(startUrl);
    while (true) {
      if (Date.now() - lastNewJs > idleNoNewJsMs) break; // no new on-target artifact for the idle window
      if (Date.now() > hardDeadline) break; // safety ceiling
      if (pages >= maxPages) break;
      const url = frontier.shift();
      if (!url) {
        if (inflight <= 0 && pendingSaves <= 0) break; // nothing queued, loading, or still being saved/harvested -> done
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
        noteLanding(await currentUrl()); // followed an HTTP/JS redirect? bring that same-domain landing host into scope
        await clickAll();
        await waitIdle();
        await clickAll(); // second pass: click the buttons the first pass revealed (expanded menus, wizard steps)
        await waitIdle();
        noteLanding(await currentUrl()); // a click may have redirected us cross-subdomain too
        await captureInline();
        await collectLinks();
      } catch {
        /* a bad page must not stop the crawl */
      }
    }

    await Promise.allSettled(saves);
    await prefetchChunks(); // enumerate + fetch lazy Webpack/Vite chunks never triggered by navigation
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
  onBody?: (text: string) => void,
): Promise<void> {
  try {
    const { body, base64Encoded } = await cdp.send<any>("Network.getResponseBody", { requestId });
    const buf = base64Encoded ? Buffer.from(body, "base64") : Buffer.from(body, "utf8");
    const name = fileNameFor(url, usedNames);
    const text = buf.toString("utf8");
    writeFileSync(join(jsDir, name), buf);
    manifest[url] = name;
    if (onBody) onBody(text); // seed any in-scope route URLs this bundle references
    await maybeSaveSourceMap(url, text, jsDir, name);
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
