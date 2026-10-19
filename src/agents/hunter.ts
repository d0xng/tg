import { join } from "path";
import { readFileSync, writeFileSync, statSync, rmSync, existsSync } from "fs";
import { agents, caps, PROMPTS_DIR, timeouts, type AgentSpec } from "../config.ts";
import { runClaude, runCodex, runDeepSeek } from "../cli.ts";
import { runLimited } from "../util/pool.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

// The hunter stage works each lead through an ESCALATION CHAIN of models, cheapest/weakest first,
// strongest last. The first model to confirm an end-to-end PoC wins and the lead stops there -- no
// point spending a stronger model on an already-confirmed bug. A lead NO model has confirmed yet
// escalates to the next model, so a lead opus-4-6 cannot crack still gets a shot from opus-4-8 and then
// opus-5 (depth as always). Leads run in parallel (each its own sequential chain) under the claude
// concurrency cap; the confirming model writes findings/<leadbase>__<tag>.md, which a dedup pass
// canonicalizes to findings/<leadbase>.md with the confirming model recorded.

const tagOf = (spec: AgentSpec): string => spec.role.replace(/^hunter-/, "");

export async function runHunters(run: Run): Promise<number> {
  const leadFiles = run.listMd("leads");
  if (!leadFiles.length) {
    log("[hunters] no leads to hunt");
    return 0;
  }
  const methodology = readFileSync(join(PROMPTS_DIR, "hunter.md"), "utf8");
  // weakest/cheapest -> strongest; the roster is defined strongest-first, so reverse it to escalate up.
  const chain = [...agents.hunters].reverse();
  log(`[hunters] ${leadFiles.length} lead(s); escalation chain: ${chain.map(tagOf).join(" -> ")}`);

  const tasks = leadFiles.map((leadFile) => () => huntLeadEscalating(run, chain, leadFile, methodology));
  await runLimited(tasks, Math.max(caps.hunterConcurrency, 1)); // N leads in parallel; each lead escalates sequentially (early-exit)

  const confirmed = dedupeFindings(run);
  run.state.counts.findings = confirmed;
  run.state.findingsByType = run.classifyFindings();
  run.save();
  return confirmed;
}

// One lead through the chain: stop at the first model that writes a finding for it.
async function huntLeadEscalating(run: Run, chain: AgentSpec[], leadFile: string, methodology: string): Promise<void> {
  const leadBase = leadFile.replace(/\.md$/, "");
  const findingsDir = run.sub("findings");
  const tried: string[] = [];
  for (const spec of chain) {
    const tag = tagOf(spec);
    const outName = `${leadBase}__${tag}.md`;
    await huntOneLead(run, spec, leadFile, methodology, outName);
    const out = join(findingsDir, outName);
    const confirmed = existsSync(out);
    jsonl(run.logFile, { stage: "hunting", event: "lead:attempt", lead: leadBase, model: tag, confirmed });
    if (confirmed) {
      try {
        let body = readFileSync(out, "utf8").trimEnd();
        body += `\n\n---\nConfirmed by: ${tag}`;
        if (tried.length) body += ` | no finding from: ${tried.join(", ")}`;
        writeFileSync(out, body + "\n");
      } catch {
        /* ignore */
      }
      log(`[hunters] ${leadBase}: confirmed by ${tag}${tried.length ? ` (after ${tried.join(", ")} found nothing)` : ""}`);
      return;
    }
    tried.push(tag);
  }
  log(`[hunters] ${leadBase}: unconfirmed by all (${tried.join(", ")})`);
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
    const res =
      spec.provider === "deepseek"
        ? await runDeepSeek(spec, prompt, { cwd: run.dir, addDirs: ["/opt/huntline/skills"], timeoutMs: timeouts.hunterMs })
        : spec.provider === "claude"
          ? await runClaude(spec, prompt, { cwd: run.dir, addDirs: ["/opt/huntline/skills"], timeoutMs: timeouts.hunterMs })
          : await runCodex(spec, prompt, {
              cwd: run.dir,
              sandbox: "workspace-write", // network enabled per codex config; writes stay in the workspace
              outFile: join(run.sub("logs"), `hunter-${spec.role}-${leadFile}.last.txt`),
              timeoutMs: timeouts.hunterMs,
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
