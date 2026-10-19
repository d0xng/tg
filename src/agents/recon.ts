import { readFileSync } from "fs";
import { join } from "path";
import { agents, PROMPTS_DIR } from "../config.ts";
import { runClaude } from "../cli.ts";
import { notify } from "../telegram.ts";
import { expandScope } from "../recon/expand.ts";
import { Run } from "../run.ts";
import { orchestrate } from "../orchestrator.ts";
import { log, warn } from "../log.ts";

// The recon agent is the conversational front of the pipeline. Each Telegram message is appended to a
// per-chat transcript and answered by a Claude agent (recon.md). The operator chats freely; when the
// scope is clear the agent emits a `@@LAUNCH {hosts,wildcards}` directive on its last line, which we
// strip (the operator never sees it), expand (wildcards -> subfinder|httpx live hosts), and run through
// orchestrate() host by host. One run at a time.

interface Turn {
  role: "operator" | "recon";
  content: string;
}
const histories = new Map<number, Turn[]>();
const MAX_TURNS = 24;
let busy = false;

export async function handleMessage(text: string, chatId: number): Promise<void> {
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
    const res = await runClaude(agents.recon, prompt, {
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
    await launch(dir);
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
