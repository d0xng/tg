import type { AgentSpec } from "./config.ts";
import { codexEffortConfig } from "./config.ts";
import { log, warn } from "./log.ts";

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

// Run a subprocess, feed `stdin`, capture stdout/stderr, enforce a timeout. The agents never return
// their answer over stdout anyway (they write artifacts to the run dir); stdout is only for logs.
export async function spawnCapture(
  cmd: string[],
  opts: { cwd?: string; stdin?: string; timeoutMs?: number; env?: Record<string, string> } = {},
): Promise<CliResult> {
  const proc = Bun.spawn(cmd, {
    cwd: opts.cwd,
    stdin: opts.stdin ? new TextEncoder().encode(opts.stdin) : "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, ...(opts.env ?? {}) },
  });

  let timedOut = false;
  const timer = opts.timeoutMs
    ? setTimeout(() => {
        timedOut = true;
        proc.kill();
      }, opts.timeoutMs)
    : null;

  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (timer) clearTimeout(timer);
  return { code, stdout, stderr, timedOut };
}

// Codex (GPT) headless. cwd is the agent's workspace; workspace-write lets it read js/ and write
// leads/ there, with no network (the js-analyzer is pure local read -> write). Prompt via stdin to
// dodge ARG_MAX. The provider-neutral methodology is injected in the prompt (Codex won't auto-load
// .claude skills).
export async function runCodex(
  spec: AgentSpec,
  prompt: string,
  opts: { cwd: string; sandbox?: "read-only" | "workspace-write" | "danger-full-access"; outFile?: string; timeoutMs?: number },
): Promise<CliResult> {
  const args = [
    "codex",
    "exec",
    "--cd",
    opts.cwd,
    "--skip-git-repo-check",
    "-s",
    opts.sandbox ?? "workspace-write",
    "-m",
    spec.model,
    "-c",
    codexEffortConfig,
  ];
  if (opts.outFile) args.push("-o", opts.outFile);
  args.push("-"); // read prompt from stdin
  log(`[${spec.role}] codex exec model=${spec.model} cwd=${opts.cwd}`);
  const r = await spawnCapture(args, { stdin: prompt, timeoutMs: opts.timeoutMs });
  if (r.timedOut) warn(`[${spec.role}] codex timed out`);
  return r;
}

// Claude Code (Opus) headless, authed via Max. bypassPermissions = autonomous; the safety boundary
// is the Non-Destructive contract in the injected prompt, not an interactive gate. Prompt via stdin.
export async function runClaude(
  spec: AgentSpec,
  prompt: string,
  opts: { cwd: string; addDirs?: string[]; allowedTools?: string[]; timeoutMs?: number },
): Promise<CliResult> {
  // Running as root blocks --permission-mode bypassPermissions ("--dangerously-skip-permissions
  // cannot be used with root/sudo"). Instead allow-list the tools the agents need so they run
  // headless without prompts: shell (curl), file IO, search, web, and sub-agents.
  const tools = opts.allowedTools ?? ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Task"];
  const args = [
    "claude",
    "-p",
    "--model",
    spec.model,
    "--output-format",
    "json",
    "--allowedTools",
    tools.join(" "),
  ];
  for (const d of opts.addDirs ?? []) args.push("--add-dir", d);
  log(`[${spec.role}] claude -p model=${spec.model} cwd=${opts.cwd}`);
  const r = await spawnCapture(args, { cwd: opts.cwd, stdin: prompt, timeoutMs: opts.timeoutMs });
  if (r.timedOut) warn(`[${spec.role}] claude timed out`);
  return r;
}
