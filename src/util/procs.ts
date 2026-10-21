import { readdirSync, readlinkSync } from "fs";

// Process housekeeping keyed on working directory. Every process a run spawns (the stage agents, and
// whatever THEY spawn: Xvfb, chrome, chromedriver, cat, ...) inherits a cwd inside the run directory,
// so /proc/<pid>/cwd is a reliable, kill-safe marker for "this process belongs to this run". The serve
// and the terminal launcher run from /opt/huntline (not a run subdir), so they are never matched.

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

// All PIDs whose cwd is the run dir or any subdir of it (never this process itself).
export function pidsWithCwdUnder(dir: string): number[] {
  const out: number[] = [];
  let entries: string[] = [];
  try {
    entries = readdirSync("/proc").filter((p) => /^\d+$/.test(p));
  } catch {
    return out;
  }
  const self = process.pid;
  for (const p of entries) {
    const pid = Number(p);
    if (pid === self) continue;
    try {
      const cwd = readlinkSync(`/proc/${p}/cwd`);
      if (cwd === dir || cwd.startsWith(dir + "/")) out.push(pid);
    } catch {
      /* process gone or /proc entry not readable */
    }
  }
  return out;
}

// Kill everything a run left behind: SIGTERM, a short grace period, then SIGKILL anything still there
// (re-scanned, so children that re-sessioned or were mid-spawn are caught too). Returns how many PIDs
// were signalled. Safe to call from a run's finally and from the watchdog on a dead run.
export async function killRunProcesses(dir: string, graceMs = 3000): Promise<number> {
  const pids = pidsWithCwdUnder(dir);
  if (!pids.length) return 0;
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
  await delay(graceMs);
  for (const pid of pidsWithCwdUnder(dir)) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* gone */
    }
  }
  return pids.length;
}
