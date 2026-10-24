import { readdirSync, readlinkSync, readFileSync, statSync } from "fs";
import { basename, join } from "path";

// Process housekeeping keyed on working directory. Every process a run spawns (the stage agents, and
// whatever THEY spawn: Xvfb, chrome, chromedriver, cat, ...) inherits a cwd inside the run directory,
// so /proc/<pid>/cwd is a reliable marker for "this process belongs to this run". The serve and the
// terminal launcher run from /opt/huntline (not a run subdir), so they are never matched.
//
// cwd alone is NOT kill-safe, and that was a live footgun: `cd runs/<id>/findings` to read the evidence
// puts the operator's own shell inside the match set, and the next reap SIGKILLs it together with the
// ssh session holding it. A candidate now has to clear the guards below as well.

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Programs huntline never spawns as a stage tool, and whose death takes the operator's work with it.
// `bash` is deliberately ABSENT: an agent's own `bash -c` runs with cwd in the run dir and must stay
// reapable. Interactive shells are excluded by the session-leader guard instead, which is exact -- a
// login shell leads its own session (sid == pid) and a spawned agent never does. Verified against live
// processes: the operator's bash had sid == pid, every claude stage agent carried the launcher's sid.
const NEVER_REAP = new Set([
  "sshd", "ssh", "mosh-server", "tmux", "screen", "script", "login", "su", "sudo", "agetty",
  "systemd", "init", "vi", "vim", "nvim", "emacs", "nano", "less", "more", "man",
]);

interface ProcFacts {
  ppid: number;
  sid: number;
  name: string;
}

// ppid, session id and executable name for one pid, or null if it vanished mid-read. comm in
// /proc/<pid>/stat is parenthesised and may itself contain spaces and parens, so the numeric fields are
// parsed from the LAST ')'. Splitting the whole line on whitespace is the classic bug here.
function procFacts(pid: number): ProcFacts | null {
  let stat: string;
  try {
    stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  } catch {
    return null;
  }
  const close = stat.lastIndexOf(")");
  if (close < 0) return null;
  const comm = stat.slice(stat.indexOf("(") + 1, close);
  const f = stat.slice(close + 2).split(" "); // f[0]=state f[1]=ppid f[2]=pgrp f[3]=session
  const ppid = Number(f[1]);
  const sid = Number(f[3]);
  if (!Number.isInteger(ppid) || !Number.isInteger(sid)) return null;
  let name = comm;
  try {
    name = basename(readlinkSync(`/proc/${pid}/exe`));
  } catch {
    /* kernel thread or unreadable exe: the truncated comm is the fallback */
  }
  return { ppid, sid, name };
}

// Us and every process above us. If a run or the watchdog was started from a shell that happens to sit
// inside the run dir, that shell is an ancestor and signalling it would kill the caller's own session.
function selfAndAncestors(): Set<number> {
  const out = new Set<number>([process.pid]);
  let pid = process.pid;
  for (let hops = 0; hops < 64; hops++) {
    const f = procFacts(pid);
    if (!f || f.ppid <= 1) break;
    out.add(f.ppid);
    pid = f.ppid;
  }
  return out;
}

// All PIDs that belong to this run AND are safe to signal: cwd inside the run dir, not us or an
// ancestor of ours, not a session leader, not one of the NEVER_REAP programs.
export function pidsWithCwdUnder(dir: string): number[] {
  const out: number[] = [];
  let entries: string[] = [];
  try {
    entries = readdirSync("/proc").filter((p) => /^\d+$/.test(p));
  } catch {
    return out;
  }
  const mine = selfAndAncestors();
  for (const p of entries) {
    const pid = Number(p);
    if (pid <= 1 || mine.has(pid)) continue;
    let cwd: string;
    try {
      cwd = readlinkSync(`/proc/${p}/cwd`);
    } catch {
      continue; // process gone or /proc entry not readable
    }
    if (cwd !== dir && !cwd.startsWith(dir + "/")) continue;
    const f = procFacts(pid);
    if (!f) continue; // exited between the cwd read and the stat read
    if (f.sid === pid) continue; // session leader: a login shell or detached multiplexer, never ours
    if (NEVER_REAP.has(f.name)) continue;
    out.push(pid);
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
