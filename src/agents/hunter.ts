import { join } from "path";
import { readFileSync, writeFileSync } from "fs";
import { agents, caps, PROMPTS_DIR, timeouts, type AgentSpec } from "../config.ts";
import { runClaude, runCodex } from "../cli.ts";
import { runLimited } from "../util/pool.ts";
import { jsonl, log, warn } from "../log.ts";
import type { Run } from "../run.ts";

// The hunter stage: three hunters, each a different model (Opus 4.6 + Opus 5.8 + GPT), validate and
// exploit the js-analyzer's leads. A lead with a confirmed end-to-end PoC that demonstrates impact
// becomes a finding on disk. Leads are distributed round-robin across the three models so each lead
// is worked once by one model (cheapest on quota); high-value leads can later be fanned to all three
// plus a conglomeration pass. Each provider runs under its own soft concurrency cap.

export async function runHunters(run: Run): Promise<number> {
  const leadFiles = run.listMd("leads");
  if (!leadFiles.length) {
    log("[hunters] no leads to hunt");
    return 0;
  }
  const methodology = readFileSync(join(PROMPTS_DIR, "hunter.md"), "utf8");
  const hunters = agents.hunters;

  // Round-robin leads -> hunters, then bucket tasks by provider so each pool paces independently.
  const byProvider: Record<"claude" | "codex", (() => Promise<void>)[]> = { claude: [], codex: [] };
  leadFiles.forEach((leadFile, i) => {
    const spec = hunters[i % hunters.length];
    byProvider[spec.provider].push(() => huntOneLead(run, spec, leadFile, methodology));
  });

  log(`[hunters] ${leadFiles.length} leads across ${hunters.length} models (claude x${byProvider.claude.length}, codex x${byProvider.codex.length})`);
  await Promise.all([
    runLimited(byProvider.claude, caps.claudeConcurrency),
    runLimited(byProvider.codex, caps.codexConcurrency),
  ]);

  const findings = run.listMd("findings").length;
  run.state.counts.findings = findings;
  run.state.findingsByType = run.classifyFindings();
  run.save();
  return findings;
}

async function huntOneLead(run: Run, spec: AgentSpec, leadFile: string, methodology: string): Promise<void> {
  const leadContent = readFileSync(join(run.sub("leads"), leadFile), "utf8");
  const prompt = [
    methodology,
    "",
    "----- THIS RUN -----",
    `Target domain: ${run.state.domain}`,
    "Scope (authorized):",
    run.state.scope,
    "",
    "Your workspace is the current working directory. Write confirmed findings to findings/.",
    "",
    `----- LEAD TO WORK (leads/${leadFile}) -----`,
    leadContent,
  ].join("\n");

  jsonl(run.logFile, { stage: "hunting", event: "hunter:start", hunter: spec.role, lead: leadFile });
  try {
    const res =
      spec.provider === "claude"
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
