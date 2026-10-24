import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { agents, PROMPTS_DIR, RUNS_DIR } from "../config.ts";
import { runAgent } from "../cli.ts";
import { notify } from "../telegram.ts";
import { expandTargets } from "../recon/expand.ts";
import { Run } from "../run.ts";
import { orchestrate } from "../orchestrator.ts";
import { liveRunDirs, ownerAlive, runActivityAgeMin } from "../util/procs.ts";
import { owesWork, pendingWork } from "../pending.ts";
import { pendingLines, resumeRun, resumeSummary } from "../resume.ts";
import { findRuns, stopRun, stopSummary } from "../stop.ts";
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
// Runs with a resume in flight. This is NOT a concurrency policy: several runs may resume at once, and
// several may overlap a fresh run, because that is how d0x works the subscriptions on purpose. It only
// stops the SAME run being resumed twice at the same time, which would pay twice for the same findings.
const resuming = new Set<string>();

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

/**
 * Finished runs that still owe validations or reports, with their ids, so the operator can act from the
 * same chat the watchdog alerted in. Pure disk: no LLM, no process, instant.
 */
export function owedReport(): string {
  const TERMINAL = new Set(["done", "error"]);
  let dirs: string[] = [];
  try {
    dirs = readdirSync(RUNS_DIR).filter((d) => /\dZ_/.test(d));
  } catch {
    /* no runs dir yet */
  }
  dirs.sort().reverse();
  const lines: string[] = [];
  for (const d of dirs) {
    let st: any;
    try {
      st = JSON.parse(readFileSync(join(RUNS_DIR, d, "run.json"), "utf8"));
    } catch {
      continue;
    }
    if (!TERMINAL.has(st.stage)) continue;
    const p = pendingWork(join(RUNS_DIR, d));
    if (!owesWork(p)) continue;
    lines.push(`- ${st.domain}: ${p.needValidation.length} to validate, ${p.needReport.length} to report`);
    lines.push(`  resume ${d}`);
  }
  if (!lines.length) return "No finished run owes any work.";
  return [
    "Finished runs that still owe work:",
    ...lines,
    "",
    'Send "resume <runId>" to do only what is missing, or "resume <runId> dry" to see it first.',
  ].join("\n");
}

const DRY = /^(dry|dry-run|--dry-run)$/i;
const ALL = /^(all|--all)$/i;

export async function handleMessage(text: string, chatId: number): Promise<void> {
  // Status command: answered instantly from disk, never routed to the recon LLM, never touches busy,
  // so it works even while a run is in flight.
  const cmd = text.trim().toLowerCase();
  if (cmd === "status" || cmd === "/status" || cmd === "estado" || cmd === "ping") {
    await notify(statusReport());
    return;
  }
  // Stop, answered without the LLM like `status`: the point of it is the moment you change your mind and
  // want the subscription back, so it cannot wait behind an LLM turn.
  //   stop                     -> what is running, and how to stop it
  //   stop <runId|domain>      -> stop the newest run still going for that
  //   stop <runId|domain> all  -> stop every run still going for that
  const stopTok = text.trim().replace(/^\//, "").split(/\s+/);
  if (stopTok[0] && stopTok[0].toLowerCase() === "stop") {
    const args = stopTok.slice(1);
    const all = args.some((a) => ALL.test(a));
    const needle = args.find((a) => !ALL.test(a));
    if (!needle) {
      await notify([statusReport(), "", 'Send "stop <runId or domain>" to stop one, or add "all" for every run on that domain.'].join("\n"));
      return;
    }
    const matches = findRuns(needle);
    if (!matches.length) {
      await notify(`Nothing matches "${needle}". Send "status" to see what is running.`);
      return;
    }
    const live = matches.filter((m) => !m.terminal);
    if (!live.length) {
      await notify(
        [`${matches.length} run(s) match "${needle}" and all of them are already finished:`, ...matches.slice(0, 6).map((m) => `- ${m.stage}: ${m.id}`)].join("\n"),
      );
      return;
    }
    const targets = all ? live : [live[0]];
    const head = live.length > 1 && !all ? [`${live.length} runs are still going; stopping the newest. Add "all" for every one.`] : [];
    const lines: string[] = [];
    for (const m of targets) {
      try {
        lines.push(stopSummary(await stopRun(m.id)));
      } catch (e) {
        lines.push(`${m.id}: stop failed, ${String(e)}`);
      }
    }
    await notify([...head, ...lines].join("\n"));
    return;
  }

  // Resume, answered without the LLM like `status`. The watchdog's "this run owes work" alert arrives in
  // this chat, on a phone, so acting on it has to be possible from here instead of requiring an ssh
  // session. Parsed from the RAW text and never from the lowercased copy, because a run id carries an
  // uppercase T and Z.
  //   resume                -> list the runs that owe work, with their ids
  //   resume <runId> dry    -> what it would do, spends nothing
  //   resume <runId>        -> do only what is missing
  const tok = text.trim().replace(/^\//, "").split(/\s+/);
  if (tok[0] && tok[0].toLowerCase() === "resume") {
    const args = tok.slice(1);
    const dry = args.some((a) => DRY.test(a));
    const id = args.find((a) => !DRY.test(a));
    if (!id) {
      await notify(owedReport());
      return;
    }
    let run: Run;
    try {
      run = Run.load(id);
    } catch {
      await notify(`No run called "${id}". Send "resume" with no id to list the ones that owe work.`);
      return;
    }
    const p = pendingWork(run.dir);
    if (dry) {
      await notify(
        [
          `${run.state.domain} (${id})`,
          `${p.needValidation.length} to validate, ${p.needReport.length} to report.`,
          ...pendingLines(p),
          owesWork(p) ? "(nothing spent)" : "nothing pending",
        ].join("\n"),
      );
      return;
    }
    if (!owesWork(p)) {
      await notify(`${run.state.domain}: nothing pending.`);
      return;
    }
    if (resuming.has(id)) {
      await notify(`${run.state.domain}: a resume is already running for that run.`);
      return;
    }
    resuming.add(id);
    await notify(
      `Resuming ${run.state.domain}: ${p.needValidation.length} to validate, ${p.needReport.length} to report. I will report back when it finishes.`,
    );
    // Detached on purpose, exactly like launch(): awaiting here would block the poll loop for the whole
    // resume and the bot would go mute. Not gated on `busy` either, because running several at once is
    // deliberate here.
    resumeRun(run)
      .then((r) => notify(resumeSummary(run, r)))
      .catch((e) => notify(`Resume failed on ${run.state.domain}: ${String(e)}`))
      .finally(() => resuming.delete(id));
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
    // Same expansion the terminal uses, so a wildcard resolves identically on both paths.
    const list = await expandTargets(
      [...(dir.hosts ?? []), ...(dir.wildcards ?? []).map((w) => (w.includes("*") ? w : `*.${w}`))],
      (m) => notify(`Recon: ${m}`),
    );
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
