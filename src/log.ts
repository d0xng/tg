import { appendFileSync } from "fs";

export function ts(): string {
  return new Date().toISOString();
}

export function log(...a: unknown[]): void {
  console.log(ts(), ...a);
}
export function warn(...a: unknown[]): void {
  console.warn(ts(), "WARN", ...a);
}
export function err(...a: unknown[]): void {
  console.error(ts(), "ERR ", ...a);
}

// Append one event to a run's JSONL log (the source of truth, survives compaction/restart).
export function jsonl(file: string, event: Record<string, unknown>): void {
  try {
    appendFileSync(file, JSON.stringify({ t: ts(), ...event }) + "\n");
  } catch {
    /* best effort */
  }
}
