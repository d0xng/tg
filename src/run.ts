import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { RUNS_DIR } from "./config.ts";
import { ts } from "./log.ts";

export type Stage =
  | "created"
  | "crawling"
  | "analyzing"
  | "hunting"
  | "validating"
  | "reporting"
  | "done"
  | "error";

export interface RunState {
  id: string;
  domain: string;
  startUrl: string;
  scope: string;
  stage: Stage;
  createdAt: string;
  updatedAt: string;
  counts: { jsFiles: number; leads: number; findings: number };
  findingsByType: Record<string, number>;
  error?: string;
  /**
   * Agent invocations that never produced a RESULT: a 429 session limit, a provider overload, a
   * timeout. These are NOT findings about the target, and the difference is the whole point: a
   * validator that 429s used to be tallied as "invalid", which turned a quota error into a verdict of
   * "false positive" and let the run finish as `done`. Six Uber candidates were written off that way
   * on 2026-10-22. Anything in here means the stage's result is incomplete, so the run must not end
   * `done`, and whatever is listed is worth re-running once the limit resets.
   */
  failures?: string[];
}

// The funnel on disk. Every stage reads the previous stage's directory and writes its own.
const FUNNEL = ["js", "notes", "leads", "findings", "reports", "logs"] as const;

export class Run {
  state: RunState;
  dir: string;

  constructor(state: RunState) {
    this.state = state;
    this.dir = join(RUNS_DIR, state.id);
  }

  static create(domainOrUrl: string, scope: string): Run {
    const startUrl = normalizeUrl(domainOrUrl);
    const domain = new URL(startUrl).hostname;
    const id =
      new Date().toISOString().replace(/[:.]/g, "-") +
      "_" +
      domain.replace(/[^a-z0-9.-]/gi, "_");
    const state: RunState = {
      id,
      domain,
      startUrl,
      scope,
      stage: "created",
      createdAt: ts(),
      updatedAt: ts(),
      counts: { jsFiles: 0, leads: 0, findings: 0 },
      findingsByType: {},
    };
    const run = new Run(state);
    mkdirSync(run.dir, { recursive: true });
    for (const d of FUNNEL) mkdirSync(join(run.dir, d), { recursive: true });
    writeFileSync(join(run.dir, "scope.md"), `# Scope\n\ndomain: ${domain}\nstart: ${startUrl}\n\n${scope}\n`);
    run.save();
    return run;
  }

  static load(id: string): Run {
    const state = JSON.parse(readFileSync(join(RUNS_DIR, id, "run.json"), "utf8")) as RunState;
    return new Run(state);
  }

  sub(name: (typeof FUNNEL)[number]): string {
    return join(this.dir, name);
  }

  get logFile(): string {
    return join(this.dir, "logs", "run.jsonl");
  }

  save(): void {
    this.state.updatedAt = ts();
    writeFileSync(join(this.dir, "run.json"), JSON.stringify(this.state, null, 2));
  }

  setStage(s: Stage): void {
    this.state.stage = s;
    this.save();
  }

  // Record an agent invocation that failed to produce a result, and persist it immediately: run.json is
  // what a later `validate-run`/`report-run` reads to know what still needs doing, and what the operator
  // sees when a run ends `error`. Deduped, because six validators hitting the same session limit is one
  // fact, not six.
  noteFailure(msg: string): void {
    const f = this.state.failures ?? (this.state.failures = []);
    if (!f.includes(msg)) f.push(msg);
    this.save();
  }

  // Count the markdown leads the js-analyzer wrote (ignore empties / hidden files).
  countLeads(): number {
    return this.listMd("leads").length;
  }

  listMd(dir: (typeof FUNNEL)[number]): string[] {
    const p = this.sub(dir);
    if (!existsSync(p)) return [];
    return readdirSync(p).filter((f) => f.endsWith(".md") && !f.startsWith("."));
  }

  // Tally findings by their frontmatter `class:` for the "N findings: idor x2, ssrf x1" notification.
  classifyFindings(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const f of this.listMd("findings")) {
      const txt = readFileSync(join(this.sub("findings"), f), "utf8");
      const m = txt.match(/^---[\s\S]*?\bclass:\s*([a-z0-9-]+)/im);
      const cls = m ? m[1].toLowerCase() : "other";
      out[cls] = (out[cls] ?? 0) + 1;
    }
    return out;
  }
}

export function normalizeUrl(s: string): string {
  const t = s.trim();
  if (/^https?:\/\//i.test(t)) return t;
  return "https://" + t.replace(/^\/+/, "");
}
