import { log, warn } from "../log.ts";

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
