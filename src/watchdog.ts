import { readdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { RUNS_DIR } from "./config.ts";
import { liveRunDirs, ownerAlive, runActivityAgeMin, killRunProcesses } from "./util/procs.ts";
import { owesWork, pendingWork } from "./pending.ts";
import { notify } from "./telegram.ts";
import { log } from "./log.ts";

// Watchdog: one pass, run from cron (ops/huntline-watchdog.cron) every few minutes, from /opt/huntline so
// bun auto-loads .env and notify() has the Telegram creds. It is the answer to "how do I know a run died
// and nothing told me". For each non-terminal run it decides, with no LLM, whether the run is still making
// progress using the same two disk//proc signals statusReport uses:
//   - a live STAGE child (claude/codex with cwd in the run dir), or
//   - file activity (js/ leads/ findings/ run.json mtime) within STALL_MIN minutes.
// A non-terminal run with neither for STALL_MIN is wedged/dead: the terminal-SIGHUP case the orchestrator's
// own finally can never reach (its process is gone), or a crawl that stopped progressing. For each such run:
//   1. reap its leftover process tree (killRunProcesses: chrome/Xvfb/cat orphans, plus any hung child whose
//      death unblocks a serve still awaiting it),
//   2. mark run.json stage=error so it is cleaned once and never re-alerted,
//   3. if the stall is recent (<= ALERT_FRESH_MIN), add it to a single Telegram alert.
// Old corpses (stalled longer than ALERT_FRESH_MIN, e.g. the backlog on the very first run) are cleaned
// SILENTLY. Healthy runs are never touched. The watchdog stays silent when nothing fresh died; use `status`
// on Telegram for the live picture at any time.

const STALL_MIN = Number(process.env.WATCHDOG_STALL_MIN ?? 15);
const ALERT_FRESH_MIN = Number(process.env.WATCHDOG_ALERT_FRESH_MIN ?? 120);
// A run whose owner process is ALIVE is never killed, however quiet it is. Past this many minutes of
// silence it is reported instead, so the operator can look. Killing on a guess is the failure this
// whole mechanism exists to stop.
const SILENT_MIN = Number(process.env.WATCHDOG_SILENT_MIN ?? 90);
// How many owed runs to name in one message before collapsing the rest into a count.
const PENDING_LIST_MAX = Number(process.env.WATCHDOG_PENDING_LIST_MAX ?? 8);
const TERMINAL = new Set(["done", "error"]);

async function main() {
  let dirs: string[] = [];
  try {
    dirs = readdirSync(RUNS_DIR).filter((d) => /\dZ_/.test(d));
  } catch {
    return; // no runs dir yet
  }
  const live = liveRunDirs(RUNS_DIR);
  const running: string[] = [];
  const freshStalls: string[] = [];
  const silent: string[] = [];
  // Finished runs that still owe validations or reports. Detection is automatic; SPENDING is not, on
  // purpose: an auto-resume would burn the whole backlog unasked, and worse, resuming old runs while a
  // fresh one is in flight makes both compete for the same subscription and hit the very session limit
  // this is recovering from. So the cron finds the work and hands over the command; the operator decides.
  const owed: string[] = [];
  let owedMore = 0;
  let wedged = 0;

  for (const d of dirs) {
    const full = join(RUNS_DIR, d);
    let st: any;
    try {
      st = JSON.parse(readFileSync(join(full, "run.json"), "utf8"));
    } catch {
      continue; // unreadable run.json, skip
    }
    if (TERMINAL.has(st.stage)) {
      // A finished run can still owe work: a 429 leaves findings unvalidated and VALID findings
      // unreported, and nothing ever came back to them because nobody knew. Say it once.
      if (!st.pendingNotifiedAt) {
        const p = pendingWork(full);
        if (owesWork(p)) {
          const line = `- ${st.domain}: ${p.needValidation.length} to validate, ${p.needReport.length} VALID without a report  [${d}]`;
          if (owed.length < PENDING_LIST_MAX) owed.push(line);
          else owedMore++;
          try {
            st.pendingNotifiedAt = new Date().toISOString();
            writeFileSync(join(full, "run.json"), JSON.stringify(st, null, 2));
          } catch {
            /* unwritable run.json: it will be reported again next pass, which is the safe direction */
          }
        }
      }
      continue;
    }

    const age = runActivityAgeMin(full);

    // 1. The owner process is alive, so the run is alive. No threshold is involved, and that is the
    //    point: the orchestrator runs with its cwd at the repo root so liveRunDirs can never see it, and
    //    at a stage boundary there is no agent to see either, so every inferred signal reads "dead"
    //    while the run is simply mid-flight. That inference killed a confirmed IDOR's validator on
    //    2026-10-24 and cost nine VALID findings their reports two days earlier.
    if (ownerAlive(st.owner)) {
      running.push(`${st.domain} (${st.stage})`);
      if (age > SILENT_MIN) {
        silent.push(`- ${st.domain}: ${st.stage}, owner pid ${st.owner.pid} is alive but nothing has been written for ${age}m`);
        log(`[watchdog] ${st.domain}: owner alive, silent ${age}m -> REPORTED, not touched`);
      }
      continue;
    }
    // 2. No owner record (a run started before that field existed), but a stage agent is working it, or
    //    the run wrote something recently. Same heuristics as before, now only a fallback.
    if (live.has(full) || age <= STALL_MIN) {
      running.push(`${st.domain} (${st.stage})`);
      continue;
    }

    // Wedged/dead: reap orphans, mark it dead so it is cleaned once and not re-alerted.
    wedged++;
    const killed = await killRunProcesses(full);
    const prevStage = st.stage;
    const fresh = age <= ALERT_FRESH_MIN;
    try {
      st.stage = "error";
      st.error = `watchdog: no stage process and no file activity for ${age}m at stage ${prevStage}; marked dead${killed ? `, reaped ${killed} leftover process(es)` : ""}`;
      writeFileSync(join(full, "run.json"), JSON.stringify(st, null, 2));
    } catch {
      /* run.json unwritable; still alert */
    }
    log(`[watchdog] ${st.domain}: wedged at ${prevStage}, age ${age}m, reaped ${killed}${fresh ? " -> ALERT" : " -> silent cleanup"}`);
    if (fresh) {
      freshStalls.push(`- ${st.domain}: died at ${prevStage} (no process, last activity ${age}m ago)${killed ? `, reaped ${killed} leftover proc(s)` : ""}`);
    }
  }

  // Heartbeat to the LOG only (never Telegram): one line per pass so `tail huntline-watchdog.log` proves
  // the cron is alive even when there is nothing to report.
  log(
    `[watchdog] pass: running=${running.length} wedged=${wedged} fresh-alert=${freshStalls.length} silent=${silent.length} owed=${owed.length + owedMore}`,
  );

  if (freshStalls.length || silent.length || owed.length) {
    const body: string[] = [];
    if (freshStalls.length) body.push("Watchdog: run(s) stopped making progress and were marked dead:", ...freshStalls);
    if (silent.length) {
      if (body.length) body.push("");
      body.push("Watchdog: run(s) still owned by a live process but quiet for a long time (NOT touched):", ...silent);
    }
    if (owed.length) {
      if (body.length) body.push("");
      body.push("Watchdog: finished run(s) that still owe work (reported once, nothing was spent):", ...owed);
      if (owedMore) body.push(`- (+${owedMore} more)`);
      body.push("", "To do only what is missing, from /opt/huntline:", "  bun run src/resume-run.ts <runId> --dry-run   # see the cost first", "  bun run src/resume-run.ts <runId>");
    }
    body.push("", running.length ? "Still running: " + running.join(", ") : "No run is currently active.");
    await notify(body.join("\n"));
  }
}

main();
