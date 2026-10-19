import { join } from "path";
import { readFileSync, writeFileSync, statSync, rmSync, existsSync } from "fs";
import { agents, PROMPTS_DIR, timeouts, type AgentSpec } from "../config.ts";
import { runAgent } from "../cli.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

// The hunter stage: each lead is worked by ONE hunter, in depth. Leads are dealt round-robin across the
// roster (lead 0 -> hunter 0, lead 1 -> hunter 1, ...), and every hunter works its own share in its own
// lane, so N hunters means N leads in flight at once, one per hunter. (The per-lead escalation chain,
// where a lead walked through all three models in turn, was too slow on wall-clock and was dropped.)
// Depth comes from the methodology prompt: the hunter exhausts every angle on its lead before giving
// up. The hunter writes findings/<leadbase>__<tag>.md, which a dedup pass canonicalizes to
// findings/<leadbase>.md with the confirming model recorded.

const tagOf = (spec: AgentSpec): string => spec.role.replace(/^hunter-/, "");

export async function runHunters(run: Run): Promise<number> {
  const leadFiles = run.listMd("leads");
  if (!leadFiles.length) {
    log("[hunters] no leads to hunt");
    return 0;
  }
  const methodology = readFileSync(join(PROMPTS_DIR, "hunter.md"), "utf8");
  const hunters = agents.hunters;

  // Deal leads round-robin, then run one sequential lane per hunter, all lanes in parallel.
  const lanes = hunters.map((spec) => ({ spec, leads: [] as string[] }));
  leadFiles.forEach((leadFile, i) => lanes[i % lanes.length].leads.push(leadFile));
  log(`[hunters] ${leadFiles.length} lead(s) across ${hunters.length} hunters: ${lanes.map((l) => `${tagOf(l.spec)} x${l.leads.length}`).join(", ")}`);

  await Promise.all(
    lanes.map(async ({ spec, leads }) => {
      for (const leadFile of leads) await huntLead(run, spec, leadFile, methodology);
    }),
  );

  const confirmed = dedupeFindings(run);
  run.state.counts.findings = confirmed;
  run.state.findingsByType = run.classifyFindings();
  run.save();
  return confirmed;
}

// One lead, one hunter: record which model confirmed it (or that it stayed a lead).
async function huntLead(run: Run, spec: AgentSpec, leadFile: string, methodology: string): Promise<void> {
  const leadBase = leadFile.replace(/\.md$/, "");
  const tag = tagOf(spec);
  const outName = `${leadBase}__${tag}.md`;
  await huntOneLead(run, spec, leadFile, methodology, outName);
  const out = join(run.sub("findings"), outName);
  const confirmed = existsSync(out);
  jsonl(run.logFile, { stage: "hunting", event: "lead:attempt", lead: leadBase, model: tag, confirmed });
  if (!confirmed) {
    log(`[hunters] ${leadBase}: unconfirmed by ${tag}`);
    return;
  }
  try {
    writeFileSync(out, readFileSync(out, "utf8").trimEnd() + `\n\n---\nConfirmed by: ${tag}\n`);
  } catch {
    /* ignore */
  }
  log(`[hunters] ${leadBase}: confirmed by ${tag}`);
}

async function huntOneLead(run: Run, spec: AgentSpec, leadFile: string, methodology: string, outName: string): Promise<void> {
  const leadContent = readFileSync(join(run.sub("leads"), leadFile), "utf8");
  const prompt = [
    methodology,
    "",
    "----- THIS RUN -----",
    `Target domain: ${run.state.domain}`,
    "Scope (authorized):",
    run.state.scope,
    "",
    "Your workspace is the current working directory.",
    "IF AND ONLY IF you confirm an end-to-end PoC with real, demonstrated impact, write your finding to",
    `exactly this path: findings/${outName}  (use that exact filename, do not choose another). If you`,
    "cannot exploit the lead, write NOTHING to findings/ -- a dead lead is a valid outcome, not a file.",
    "",
    `----- LEAD TO WORK (leads/${leadFile}) -----`,
    leadContent,
  ].join("\n");

  jsonl(run.logFile, { stage: "hunting", event: "hunter:start", hunter: spec.role, lead: leadFile });
  try {
    const res = await runAgent(spec, prompt, {
      cwd: run.dir,
      addDirs: ["/opt/huntline/skills"],
      timeoutMs: timeouts.hunterMs,
      outFile: join(run.sub("logs"), `hunter-${spec.role}-${leadFile}.last.txt`), // codex only
    });
    writeFileSync(
      join(run.sub("logs"), `hunter-${spec.role}-${leadFile}.out.log`),
      `exit=${res.code} timedOut=${res.timedOut}\n==STDOUT==\n${res.stdout}\n==STDERR==\n${res.stderr}\n`,
    );
  } catch (e) {
    warn(`[hunters] ${spec.role} failed on ${leadFile}: ${String(e)}`);
  }
  jsonl(run.logFile, { stage: "hunting", event: "hunter:done", hunter: spec.role, lead: leadFile });
}

// Canonicalize per-model finding files (<leadbase>__<tag>.md) to one <leadbase>.md per lead. With the
// escalation chain there is at most one per lead; if several ever exist we keep the largest PoC.
function dedupeFindings(run: Run): number {
  const dir = run.sub("findings");
  const groups = new Map<string, { file: string; size: number }[]>();
  let strays = 0;
  for (const f of run.listMd("findings")) {
    const m = f.match(/^(.+)__([A-Za-z0-9.\-]+)\.md$/);
    if (!m) {
      strays++;
      continue;
    }
    let size = 0;
    try {
      size = statSync(join(dir, f)).size;
    } catch {
      /* ignore */
    }
    const arr = groups.get(m[1]) ?? [];
    arr.push({ file: f, size });
    groups.set(m[1], arr);
  }

  let canonical = 0;
  for (const [base, variants] of groups) {
    variants.sort((a, b) => b.size - a.size);
    try {
      writeFileSync(join(dir, `${base}.md`), readFileSync(join(dir, variants[0].file), "utf8"));
      for (const v of variants) {
        try {
          rmSync(join(dir, v.file));
        } catch {
          /* ignore */
        }
      }
      canonical++;
    } catch (e) {
      warn(`[hunters] dedupe failed for ${base}: ${String(e)}`);
    }
  }
  log(`[hunters] ${canonical} canonical finding(s) + ${strays} unnamed`);
  return canonical + strays;
}
