import { readdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { RUNS_DIR } from "./config.ts";
import { killRunProcesses, ownerAlive } from "./util/procs.ts";
import { requestStop, stopRequested } from "./util/stopflag.ts";
import { log, warn } from "./log.ts";
import type { RunState } from "./run.ts";

// Stopping a run, for the moment the operator changes their mind and wants the subscription back.
//
// Two shapes have to be handled and they are not the same:
//   - the owner is ANOTHER process (a `huntline-run@` unit, or `bun run hunt` in a shell): it can be
//     signalled, so the stop is immediate and authoritative.
//   - the owner is THIS process (a Telegram run runs inside the serve, because launch() awaits
//     orchestrate() in a detached promise): killing it would kill the bot. So the stop is cooperative:
//     the sentinel tells the orchestrator to stop at its next boundary, and killing the current stage's
//     agents makes that boundary arrive in seconds instead of after a 30 minute timeout.
// Either way the sentinel is written FIRST, so nothing starts a new stage in the gap between the kill and
// the bookkeeping.

const TERMINAL = new Set(["done", "error"]);

export interface RunMatch {
  id: string;
  domain: string;
  stage: string;
  terminal: boolean;
}

/** Runs matching an id, a domain, or a fragment of either. Newest first, non-terminal ones first. */
export function findRuns(needle: string): RunMatch[] {
  const q = needle.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  let dirs: string[] = [];
  try {
    dirs = readdirSync(RUNS_DIR).filter((d) => /\dZ_/.test(d));
  } catch {
    return [];
  }
  const out: RunMatch[] = [];
  for (const d of dirs) {
    let st: RunState;
    try {
      st = JSON.parse(readFileSync(join(RUNS_DIR, d, "run.json"), "utf8")) as RunState;
    } catch {
      continue;
    }
    const dom = (st.domain ?? "").toLowerCase();
    const hit =
      d.toLowerCase() === q ||
      dom === q ||
      dom.replace(/^www\./, "") === q.replace(/^www\./, "") ||
      d.toLowerCase().includes(q) ||
      dom.includes(q);
    if (!hit) continue;
    out.push({ id: d, domain: st.domain, stage: st.stage, terminal: TERMINAL.has(st.stage) });
  }
  // Newest first, and anything still running ahead of the corpses.
  out.sort((a, b) => (a.terminal === b.terminal ? b.id.localeCompare(a.id) : a.terminal ? 1 : -1));
  return out;
}

export interface StopResult {
  id: string;
  domain: string;
  stage: string;
  /** Already finished, so nothing was stopped. */
  alreadyTerminal: boolean;
  /** Agent/tool processes signalled. */
  reaped: number;
  /** The owner process was signalled directly (it was not us). */
  ownerKilled: boolean;
  /** We ARE the owner: the stop is cooperative and lands at the orchestrator's next boundary. */
  cooperative: boolean;
}

export async function stopRun(id: string, reason = "stopped by operator"): Promise<StopResult> {
  const dir = join(RUNS_DIR, id);
  const st = JSON.parse(readFileSync(join(dir, "run.json"), "utf8")) as RunState;
  const res: StopResult = {
    id,
    domain: st.domain,
    stage: st.stage,
    alreadyTerminal: TERMINAL.has(st.stage),
    reaped: 0,
    ownerKilled: false,
    cooperative: false,
  };
  if (res.alreadyTerminal && !ownerAlive(st.owner)) {
    log(`[stop] ${id} is already ${st.stage}, nothing to stop`);
    return res;
  }

  // Sentinel first: whatever happens next, no stage starts after this point.
  if (!stopRequested(dir)) requestStop(dir, reason);

  // The current stage's agents. This is what makes the stop immediate: the awaited runAgent returns as
  // soon as its child dies, instead of thirty minutes later.
  res.reaped = await killRunProcesses(dir);

  const owner = st.owner;
  if (ownerAlive(owner)) {
    if (owner!.pid === process.pid) {
      // A Telegram run: we are the orchestrator. Cooperative stop only.
      res.cooperative = true;
      log(`[stop] ${id}: this process owns the run, stopping cooperatively at the next stage boundary`);
    } else {
      try {
        process.kill(owner!.pid, "SIGTERM");
        await new Promise((r) => setTimeout(r, 3000));
        if (ownerAlive(owner)) process.kill(owner!.pid, "SIGKILL");
        res.ownerKilled = true;
      } catch {
        /* exited between the check and the signal, which is the outcome we wanted */
        res.ownerKilled = true;
      }
      // Reap whatever the dying owner left behind.
      res.reaped += await killRunProcesses(dir);
    }
  }

  // The owner can no longer write its own epitaph, so do it here. A cooperative stop leaves this to the
  // orchestrator, whose own throw records the reason and the stage it got to.
  if (!res.cooperative) {
    try {
      st.stage = "error";
      st.error = `${reason} (was ${res.stage})`;
      writeFileSync(join(dir, "run.json"), JSON.stringify(st, null, 2));
    } catch (e) {
      warn(`[stop] could not mark ${id}: ${String(e)}`);
    }
  }
  log(
    `[stop] ${id} (${st.domain}): reaped ${res.reaped}, owner ${res.ownerKilled ? "killed" : res.cooperative ? "is us (cooperative)" : "not running"}`,
  );
  return res;
}

/** One line per stop, for Telegram or the terminal. */
export function stopSummary(r: StopResult): string {
  if (r.alreadyTerminal && !r.ownerKilled && !r.cooperative && !r.reaped) {
    return `${r.domain}: already ${r.stage}, nothing to stop.`;
  }
  const how = r.ownerKilled
    ? "owner killed"
    : r.cooperative
      ? "will stop at the next stage boundary (seconds)"
      : "no owner process was running";
  return `${r.domain} (${r.stage}): stopped. ${r.reaped} process(es) reaped, ${how}.`;
}
