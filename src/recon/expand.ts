import { log, warn } from "../log.ts";

/** A target written as a pattern rather than a host: `*.example.com`, `https://*.example.com`. */
export function isWildcard(t: string): boolean {
  return t.includes("*");
}

/**
 * The registrable root subfinder should be asked about. `*.example.com` and `https://*.example.com/x`
 * both give `example.com`.
 *
 * Returns "" when the pattern has no resolvable root, which is the `*.natturalabs.*` case: a wildcard TLD
 * is not something subfinder can enumerate, and the Telegram path only copes with it because an LLM reads
 * it first and emits concrete roots. The terminal has no LLM, so it says so instead of guessing a TLD.
 */
export function wildcardRoot(t: string): string {
  const root = t
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/^\*+\./, "")
    .replace(/\.\*+$/, "")
    .replace(/\*/g, "")
    .replace(/^\.+|\.+$/g, "")
    .trim()
    .toLowerCase();
  return root.includes(".") ? root : "";
}

/**
 * Turn a mixed list of hosts and wildcards into the concrete https URLs to hunt, deduped by hostname and
 * capped by expandScope's RECON_MAX_HOSTS. Shared by the Telegram launch path and `bun run hunt`, so a
 * wildcard means the same thing in both; it used to work only through the bot.
 */
export async function expandTargets(
  targets: string[],
  onProgress?: (msg: string) => void | Promise<void>,
): Promise<string[]> {
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (raw: string): void => {
    const url = /^https?:\/\//i.test(raw) ? raw : "https://" + raw.replace(/^\/+/, "");
    let host: string;
    try {
      host = new URL(url).host.toLowerCase();
    } catch {
      return;
    }
    if (seen.has(host)) return;
    seen.add(host);
    out.push(url);
  };
  for (const raw of targets) {
    const t = (raw ?? "").trim();
    if (!t) continue;
    if (!isWildcard(t)) {
      add(t);
      continue;
    }
    const root = wildcardRoot(t);
    if (!root) {
      await onProgress?.(`cannot expand "${t}": no registrable root in it, give a concrete one like *.example.com`);
      continue;
    }
    await onProgress?.(`expanding *.${root} with subfinder | httpx ...`);
    const live = await expandScope(root);
    await onProgress?.(`*.${root} resolved to ${live.length} live host(s).`);
    for (const h of live) add(h);
  }
  return out;
}

// Expand a wildcard root into live hosts the way the manifesto's recon skill prescribes:
//   subfinder -silent -all -d <root> | httpx -silent -nc   (no CIDRs, ever)
// Returns deduped https URLs (one per live host), capped by RECON_MAX_HOSTS so a huge root cannot
// spawn an unbounded number of full-pipeline runs.
export async function expandScope(root: string, opts: { maxHosts?: number } = {}): Promise<string[]> {
  const maxHosts = opts.maxHosts ?? Number(process.env.RECON_MAX_HOSTS ?? 100);
  try {
    const sf = Bun.spawn(["subfinder", "-silent", "-all", "-d", root], { stdout: "pipe", stderr: "ignore" });
    const subs = (await new Response(sf.stdout).text()).split("\n").map((s) => s.trim()).filter(Boolean);
    await sf.exited;
    log(`[recon] subfinder ${root}: ${subs.length} subdomains`);
    if (!subs.length) return [];

    const hx = Bun.spawn(["httpx", "-silent", "-nc", "-no-color"], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "ignore",
    });
    hx.stdin.write(subs.join("\n") + "\n");
    hx.stdin.end();
    const live = (await new Response(hx.stdout).text()).split("\n").map((s) => s.trim()).filter(Boolean);
    await hx.exited;

    const seen = new Set<string>();
    const out: string[] = [];
    for (const raw of live) {
      const url = raw.includes("://") ? raw : "https://" + raw;
      let host: string;
      try {
        host = new URL(url).host.toLowerCase();
      } catch {
        continue;
      }
      if (seen.has(host)) continue;
      seen.add(host);
      out.push(url);
      if (out.length >= maxHosts) break;
    }
    log(`[recon] httpx ${root}: ${out.length} live hosts (cap ${maxHosts})`);
    return out;
  } catch (e) {
    warn("[recon] expandScope failed:", String(e));
    return [];
  }
}
