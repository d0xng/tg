import { existsSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join } from "path";

// A stop request, as a file in the run directory.
//
// It is a FILE and not a field in run.json because the orchestrator holds run.state in memory and
// rewrites run.json on every save(), so a flag set from another process would be overwritten by the next
// stage transition. A sentinel the owner only ever reads cannot be clobbered that way, and it also works
// when the owner is a different process entirely (a `huntline-run@` unit) or the same one (a Telegram run
// lives inside the serve process, which cannot be killed without killing the bot).
//
// Zero dependencies on purpose: the stage agents import this, and pulling the Run class or the process
// helpers in here would make that circular.

const FILE = ".stop";

export function requestStop(dir: string, reason: string): void {
  try {
    writeFileSync(join(dir, FILE), `${new Date().toISOString()} ${reason}\n`);
  } catch {
    /* best effort: the kill below is the other half of the mechanism */
  }
}

export function stopRequested(dir: string): boolean {
  return existsSync(join(dir, FILE));
}

export function stopReason(dir: string): string {
  try {
    return readFileSync(join(dir, FILE), "utf8").trim();
  } catch {
    return "";
  }
}

// Cleared when a run is resumed, or the resume would abort on the sentinel the stop left behind.
export function clearStop(dir: string): void {
  try {
    rmSync(join(dir, FILE), { force: true });
  } catch {
    /* ignore */
  }
}
