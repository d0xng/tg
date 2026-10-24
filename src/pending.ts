import { existsSync, readFileSync, readdirSync } from "fs";
import { join } from "path";
import { DECIDED, verdictOf } from "./util/verdict.ts";

// What a run still OWES, read straight off disk. The funnel directories are the state, so this needs no
// log replay and no process: a finding with no decided verdict owes a validation, and a VALID finding
// with no report owes a report. Shared by resume-run (to do the work) and the watchdog (to tell the
// operator the work exists), because the thing that actually cost findings was nobody knowing.

export interface Pending {
  /** findings/ entries whose verdict is missing or incomplete. */
  needValidation: string[];
  /** findings/ entries with a VALID verdict and no reports/ file. */
  needReport: string[];
  /** How many findings carry a VALID verdict right now. */
  valid: number;
  total: number;
}

export function pendingWork(dir: string): Pending {
  const fd = join(dir, "findings");
  const vd = join(dir, "verdicts");
  const rd = join(dir, "reports");
  let findings: string[] = [];
  try {
    findings = readdirSync(fd).filter((f) => f.endsWith(".md") && !f.startsWith("."));
  } catch {
    return { needValidation: [], needReport: [], valid: 0, total: 0 };
  }
  const needValidation: string[] = [];
  const needReport: string[] = [];
  let valid = 0;
  for (const f of findings) {
    const vf = join(vd, f);
    const tok = existsSync(vf) ? verdictOf(readFileSync(vf, "utf8")) : "";
    if (!DECIDED.has(tok)) {
      needValidation.push(f);
      continue;
    }
    if (tok !== "VALID") continue;
    valid++;
    if (!existsSync(join(rd, f))) needReport.push(f);
  }
  return { needValidation, needReport, valid, total: findings.length };
}

export function owesWork(p: Pending): boolean {
  return p.needValidation.length > 0 || p.needReport.length > 0;
}
