import type { AgentSpec } from "./config.ts";
import { accountToken, codexEffortConfig, deepseek, glm, stripAccountTag } from "./config.ts";
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
  opts: { cwd?: string; stdin?: string; timeoutMs?: number; env?: Record<string, string>; envFull?: Record<string, string> } = {},
): Promise<CliResult> {
  const proc = Bun.spawn(cmd, {
    cwd: opts.cwd,
    stdin: opts.stdin ? new TextEncoder().encode(opts.stdin) : "ignore",
    stdout: "pipe",
    stderr: "pipe",
    // envFull replaces the environment entirely (used to strip the Max OAuth token for DeepSeek); env merges.
    env: opts.envFull ?? { ...process.env, ...(opts.env ?? {}) },
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
  // An account tag ("claude-opus-5-5@a") picks WHICH subscription runs this agent; the tag never goes
  // to --model.
  const model = stripAccountTag(spec.model);
  const token = accountToken(spec.model);
  const args = [
    "claude",
    "-p",
    "--model",
    model,
    "--output-format",
    "json",
    "--allowedTools",
    tools.join(" "),
  ];
  for (const d of opts.addDirs ?? []) args.push("--add-dir", d);
  // Build the environment explicitly on the subscription path so that (a) a tagged id swaps in that
  // account's OAuth token, letting two subscriptions run in parallel, and (b) a stray ANTHROPIC_API_KEY
  // or ANTHROPIC_AUTH_TOKEN can never silently take over: the CLI ranks API keys ABOVE the OAuth token,
  // so one left in the environment would bill per-token instead of drawing on the subscription, with no
  // prompt in -p mode. Untagged ids keep the box-default CLAUDE_CODE_OAUTH_TOKEN copied from the env.
  const envFull: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || k === "ANTHROPIC_API_KEY" || k === "ANTHROPIC_AUTH_TOKEN") continue;
    envFull[k] = v;
  }
  if (token) envFull.CLAUDE_CODE_OAUTH_TOKEN = token;
  // A tag with no token behind it would quietly fall back to the box default, putting two "different"
  // accounts on the same subscription without anyone noticing. Say so instead.
  if (!token && model !== spec.model) {
    warn(`[${spec.role}] model "${spec.model}" carries an account tag but CLAUDE_OAUTH_${spec.model.slice(spec.model.indexOf("@") + 1).toUpperCase()} is unset; falling back to the box default subscription`);
  }
  log(`[${spec.role}] claude -p model=${model}${token ? " acct=tagged" : ""} cwd=${opts.cwd}`);
  const r = await spawnCapture(args, { cwd: opts.cwd, stdin: prompt, timeoutMs: opts.timeoutMs, envFull });
  if (r.timedOut) warn(`[${spec.role}] claude timed out`);
  return r;
}

// Run a model through the Claude Code CLI pointed at a third-party Anthropic-compatible endpoint, so
// that model runs AGENTIC (reusing the claude harness's tools) for mining and hunting. We strip the
// Max OAuth token and inject ANTHROPIC_BASE_URL + the provider's key, so this claude process talks to
// the provider, not Anthropic. Shared by DeepSeek and GLM; the CLI has no effort flag on this path.
async function runAnthropicCompat(
  spec: AgentSpec,
  prompt: string,
  opts: { cwd: string; addDirs?: string[]; allowedTools?: string[]; timeoutMs?: number },
  cfg: { apiKey: string; baseUrl: string },
  label: string,
): Promise<CliResult> {
  const tools = opts.allowedTools ?? ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Task"];
  const args = ["claude", "-p", "--model", spec.model, "--output-format", "json", "--allowedTools", tools.join(" ")];
  for (const d of opts.addDirs ?? []) args.push("--add-dir", d);
  const envFull: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && k !== "CLAUDE_CODE_OAUTH_TOKEN") envFull[k] = v;
  }
  envFull.ANTHROPIC_BASE_URL = cfg.baseUrl;
  envFull.ANTHROPIC_API_KEY = cfg.apiKey;
  envFull.ANTHROPIC_AUTH_TOKEN = cfg.apiKey;
  log(`[${spec.role}] claude(${label}) model=${spec.model} cwd=${opts.cwd}`);
  const r = await spawnCapture(args, { cwd: opts.cwd, stdin: prompt, timeoutMs: opts.timeoutMs, envFull });
  if (r.timedOut) warn(`[${spec.role}] ${label} timed out`);
  return r;
}

// DeepSeek via its Anthropic-compatible endpoint. DeepSeek models default to "high" effort.
export function runDeepSeek(
  spec: AgentSpec,
  prompt: string,
  opts: { cwd: string; addDirs?: string[]; allowedTools?: string[]; timeoutMs?: number },
): Promise<CliResult> {
  return runAnthropicCompat(spec, prompt, opts, deepseek, "deepseek");
}

// GLM (Zhipu / z.ai) via its Coding Plan Anthropic-compatible endpoint. GLM_API_KEY must be a Coding
// Plan key (a general open-platform key returns 1113 "no resource package"); see config.ts.
export function runGLM(
  spec: AgentSpec,
  prompt: string,
  opts: { cwd: string; addDirs?: string[]; allowedTools?: string[]; timeoutMs?: number },
): Promise<CliResult> {
  return runAnthropicCompat(spec, prompt, opts, glm, "glm");
}

// One entry point for every stage: the CLI is picked from the spec's provider, which config.ts derives
// from the model id (claude-* -> Max subscription, glm-* -> GLM Coding Plan, deepseek-* -> DeepSeek, gpt-*
// -> codex). Codex gets the workspace-write sandbox (network per codex config) and, optionally, -o outFile.
export function runAgent(
  spec: AgentSpec,
  prompt: string,
  opts: { cwd: string; addDirs?: string[]; allowedTools?: string[]; timeoutMs?: number; outFile?: string },
): Promise<CliResult> {
  switch (spec.provider) {
    case "glm":
      return runGLM(spec, prompt, opts);
    case "deepseek":
      return runDeepSeek(spec, prompt, opts);
    case "codex":
      return runCodex(spec, prompt, { cwd: opts.cwd, sandbox: "workspace-write", outFile: opts.outFile, timeoutMs: opts.timeoutMs });
    default:
      return runClaude(spec, prompt, opts);
  }
}
