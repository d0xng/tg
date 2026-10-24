import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { agents, PROMPTS_DIR, RUNS_DIR } from "../config.ts";
import { runAgent } from "../cli.ts";
import { notify } from "../telegram.ts";
import { expandScope } from "../recon/expand.ts";
import { Run } from "../run.ts";
import { orchestrate } from "../orchestrator.ts";
import { liveRunDirs, ownerAlive, runActivityAgeMin } from "../util/procs.ts";
import { log, warn } from "../log.ts";

// The recon agent is the conversational front of the pipeline. Each Telegram message is appended to a
// per-chat transcript and answered by a Claude agent (recon.md). The operator chats freely; when the
// scope is clear the agent emits a `@@LAUNCH {hosts,wildcards}` directive on its last line, which we
// strip (the operator never sees it), expand (wildcards -> subfinder|httpx live hosts), and run through
// orchestrate() host by host. The pipeline runs DETACHED (not awaited), so the poll loop stays free to
// answer messages (e.g. `status`) while a run is in flight; `busy` still serializes to one run at a time.

interface Turn {
  role: "operator" | "recon";
  content: string;
}
const histories = new Map<number, Turn[]>();
const MAX_TURNS = 24;
let busy = false;

// liveRunDirs and runActivityAgeMin live in util/procs.ts, shared with the watchdog.

// Fast, LLM-free status. A non-terminal run is ACTIVE if a stage child is working it (process cwd) or it
// showed file activity in the last ACTIVE_MIN minutes; older non-terminal runs are stale corpses and are
// only counted, not listed, so the report stays about what is actually running now.
export function statusReport(): string {
  const TERMINAL = new Set(["done", "error"]);
  const ACTIVE_MIN = 20;
  const live = liveRunDirs(RUNS_DIR);
  let dirs: string[] = [];
  try {
    dirs = readdirSync(RUNS_DIR).filter((d) => /\dZ_/.test(d));
  } catch {
    /* no runs dir yet */
  }
  dirs.sort().reverse();
  const active: string[] = [];
  let stale = 0;
  for (const d of dirs) {
    let st: any;
    try {
      st = JSON.parse(readFileSync(join(RUNS_DIR, d, "run.json"), "utf8"));
    } catch {
      continue;
    }
    if (TERMINAL.has(st.stage)) continue;
    const full = join(RUNS_DIR, d);
    const age = runActivityAgeMin(full);
    // Same liveness the watchdog uses, deliberately: `status` saying "active" while the watchdog has
    // already killed the run (ACTIVE_MIN 20 against STALL_MIN 15) was its own small lie.
    const owned = ownerAlive(st.owner);
    if (owned || live.has(full) || age <= ACTIVE_MIN) {
      const c = st.counts ?? {};
      const proc = owned
        ? `owner pid ${st.owner.pid} alive`
        : live.has(full)
          ? "process alive"
          : `last activity ${age}m ago`;
      active.push(`- ${st.domain}: ${st.stage} (js ${c.jsFiles ?? 0}, leads ${c.leads ?? 0}, findings ${c.findings ?? 0}; ${proc})`);
    } else {
      stale++;
    }
  }
  const head = busy ? "Serve: a Telegram run is in progress (busy)." : "Serve: idle, no Telegram run.";
  const parts = [head];
  parts.push(active.length ? `${active.length} run(s) active:\n` + active.join("\n") : "No run is currently active.");
  if (stale) parts.push(`(+${stale} older unfinished run(s) with no recent activity, likely dead; worth a cleanup.)`);
  return parts.join("\n");
}

export async function handleMessage(text: string, chatId: number): Promise<void> {
  // Status command: answered instantly from disk, never routed to the recon LLM, never touches busy,
  // so it works even while a run is in flight.
  const cmd = text.trim().toLowerCase();
  if (cmd === "status" || cmd === "/status" || cmd === "estado" || cmd === "ping") {
    await notify(statusReport());
    return;
  }
  const methodology = readFileSync(join(PROMPTS_DIR, "recon.md"), "utf8");
  const hist = histories.get(chatId) ?? [];
  hist.push({ role: "operator", content: text });

  const transcript = hist.slice(-MAX_TURNS).map((m) => `${m.role}: ${m.content}`).join("\n");
  const prompt = [
    methodology,
    "",
    "----- CONVERSATION SO FAR -----",
    transcript,
    "",
    "Reply now as recon, in English. Emit the @@LAUNCH directive as the final line ONLY if the scope is clear.",
  ].join("\n");

  let reply = "";
  try {
    const res = await runAgent(agents.recon, prompt, {
      cwd: "/tmp",
      allowedTools: ["Read"],
      timeoutMs: 120_000,
    });
    try {
      reply = (JSON.parse(res.stdout).result ?? "").trim();
    } catch {
      reply = res.stdout.trim();
    }
  } catch (e) {
    warn("[recon] agent call failed:", String(e));
    await notify("recon hit an error, try again in a moment.");
    return;
  }
  if (!reply) {
    await notify("...(no reply)");
    return;
  }

  const m = reply.match(/@@LAUNCH\s*(\{[\s\S]*\})\s*$/);
  const chat = reply.replace(/@@LAUNCH[\s\S]*$/, "").trim();
  if (chat) await notify(chat);
  hist.push({ role: "recon", content: reply });
  histories.set(chatId, hist);

  if (m) {
    let dir: { hosts?: string[]; wildcards?: string[] };
    try {
      dir = JSON.parse(m[1]);
    } catch (e) {
      warn("[recon] bad LAUNCH json:", m[1]);
      return;
    }
    // Detached on purpose: do NOT await the pipeline, or the poll loop blocks for the whole run and the
    // bot goes mute. launch() sets busy synchronously on entry, so a second LAUNCH is still rejected.
    launch(dir).catch((e) => warn("[recon] launch crashed:", String(e)));
  }
}

async function launch(dir: { hosts?: string[]; wildcards?: string[] }): Promise<void> {
  if (busy) {
    await notify("A run is already in progress. Wait for it to finish, then send the next scope.");
    return;
  }
  busy = true;
  try {
    const hosts = new Set<string>();
    for (const h of dir.hosts ?? []) {
      const t = h.trim();
      if (t) hosts.add(/^https?:\/\//i.test(t) ? t : "https://" + t);
    }
    for (const w of dir.wildcards ?? []) {
      const root = w.replace(/^\*\./, "").replace(/^https?:\/\//i, "").trim();
      if (!root) continue;
      await notify(`Recon: expanding *.${root} with subfinder | httpx ...`);
      const live = await expandScope(root);
      await notify(`Recon: *.${root} resolved to ${live.length} live host(s).`);
      for (const h of live) hosts.add(h);
    }
    const list = [...hosts];
    if (!list.length) {
      await notify("No live hosts to hunt.");
      return;
    }
    await notify(`Recon: ${list.length} host(s) queued. Starting.`);
    let i = 0;
    for (const h of list) {
      i++;
      log(`[recon] host ${i}/${list.length}: ${h}`);
      try {
        const run = Run.create(h, `authorized target: ${h}`);
        await orchestrate(run);
      } catch (e) {
        warn(`[recon] run failed on ${h}:`, String(e));
        await notify(`Run failed on ${h}: ${String(e)}`);
      }
    }
    await notify(`Done: ${list.length} host(s) processed.`);
  } finally {
    busy = false;
  }
}
