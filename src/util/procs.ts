import { readdirSync, readlinkSync, readFileSync, statSync } from "fs";
import { join } from "path";

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

// Run dirs that have a live STAGE child right now. Stage agents (claude/codex/glm) are spawned with
// cwd = the run dir, so /proc/<pid>/cwd points at the run they are working. We count ONLY those (cmdline
// carries the skills add-dir, or the process runs under codex), never the Xvfb/chrome/cat tools a hunter
// orphans in the run dir, so a long-dead run is not mistaken for alive. This is the authoritative
// "actually running" signal: it does not false-positive on a hunter grinding one lead for 15 minutes
// writing nothing. Shared by statusReport and the watchdog.
export function liveRunDirs(runsDir: string): Set<string> {
  const live = new Set<string>();
  let pids: string[] = [];
  try {
    pids = readdirSync("/proc").filter((p) => /^\d+$/.test(p));
  } catch {
    return live;
  }
  for (const pid of pids) {
    let cwd: string;
    try {
      cwd = readlinkSync(`/proc/${pid}/cwd`);
    } catch {
      continue; // process gone or not readable
    }
    if (!cwd.startsWith(runsDir + "/")) continue;
    let cmd = "";
    try {
      cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8");
    } catch {
      continue;
    }
    if (!cmd.includes("/opt/huntline/skills") && !cmd.includes("codex")) continue;
    // cwd may be the run dir itself or a subdir the agent cd'd into; map back to the run dir.
    const rel = cwd.slice(runsDir.length + 1).split("/")[0];
    if (rel) live.add(join(runsDir, rel));
  }
  return live;
}

// Minutes since a run dir last showed ANY file activity, or a large number if none. We take the most
// recent mtime across the run's own marker AND its output subdirs: a directory's mtime bumps whenever a
// file is added to or removed from it, so a healthy crawl (writing into js/) or a hunter (writing into
// leads/ findings/) keeps this low WITHOUT walking thousands of files, and run.json covers every stage
// transition. One stat per path, no recursion.
export function runActivityAgeMin(dir: string): number {
  const paths = [
    join(dir, "run.json"),
    join(dir, "logs"),
    join(dir, "logs", "run.jsonl"),
    join(dir, "js"),
    join(dir, "leads"),
    join(dir, "findings"),
    join(dir, "verdicts"),
    join(dir, "reports"),
  ];
  let newest = 0;
  for (const p of paths) {
    try {
      newest = Math.max(newest, statSync(p).mtimeMs);
    } catch {
      /* path may not exist yet */
    }
  }
  if (!newest) return 1e9;
  return Math.max(0, Math.round((Date.now() - newest) / 60000));
}
