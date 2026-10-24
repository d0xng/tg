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
  ];
  if (spec.effort) args.push("-c", codexEffortConfig(spec.effort));
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
  // Reasoning effort, only when the spec asks for one. Absent means the flag is not passed at all, which
  // leaves the CLI's default in charge: asking for a level and not asking are different things, and this
  // used to never be passed to claude at all.
  if (spec.effort) args.push("--effort", spec.effort);
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
// the provider, not Anthropic. Shared by DeepSeek and GLM. --effort DOES reach both of them: measured on
// this rig, low vs max moves GLM's output tokens 456 -> 1125 and DeepSeek's 788 -> 1811, with latency
// roughly doubling, so the flag is honoured through the compat shim even though neither provider reports
// thinking_tokens back in its usage block.
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
  if (spec.effort) args.push("--effort", spec.effort);
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

// DeepSeek via its Anthropic-compatible endpoint.
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

export interface AgentFailure {
  /** Short reason: "usage_limit_reached", "api 503", "timeout", "exit 1". */
  reason: string;
  /** The CLI's own sentence when it gave one, e.g. "You've hit your session limit, resets 2:30am (UTC)". */
  detail?: string;
  /** Worth ONE immediate retry on the same model (overload, capacity, 5xx) vs pointless (a quota that resets hours from now). */
  retryNow: boolean;
}

// The claude CLI with --output-format json prints one result object. Parse it tolerantly: a stray line
// before it, or a codex run with a different output shape, must never throw here.
function parseResult(stdout: string): Record<string, any> | null {
  const s = (stdout ?? "").trim();
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    /* maybe there is noise around it */
  }
  for (const line of s.split("\n").reverse()) {
    const l = line.trim();
    if (l.startsWith("{") && l.endsWith("}")) {
      try {
        return JSON.parse(l);
      } catch {
        /* keep looking */
      }
    }
  }
  return null;
}

// Momentarily unable, as opposed to out of quota for hours.
const RETRY_NOW = /overloaded|capacity|rate_limit|unavailable|internal|gateway|temporarily/i;

/**
 * Did this invocation fail to produce a RESULT, as opposed to running and concluding nothing?
 *
 * This is the distinction the pipeline used to lose, and it was expensive. Every stage decides its
 * outcome from the artifact the agent wrote (`existsSync(verdicts/x.md)`, `existsSync(findings/x.md)`),
 * so an agent that never ran looks exactly like an agent that ran and found nothing. On 2026-10-22 six
 * validator invocations on uber.com returned in half a second with
 * `api_error_status: 429, api_error: "usage_limit_reached"`, were tallied as six false positives, and
 * the run finished `done`. Run every result through this and the two cases separate.
 */
export function agentFailure(res: CliResult): AgentFailure | null {
  if (res.timedOut) return { reason: "timeout", retryNow: true };
  const o = parseResult(res.stdout);
  const status = o && typeof o.api_error_status === "number" ? o.api_error_status : 0;
  const name = o && typeof o.api_error === "string" ? o.api_error : "";
  const terminal = o && typeof o.terminal_reason === "string" ? o.terminal_reason : "";
  if (status || name || terminal === "api_error") {
    const reason = name || (status ? `api ${status}` : "api_error");
    const detail = o && typeof o.result === "string" ? o.result.trim().slice(0, 200) : undefined;
    // A session/usage limit resets hours later, so retrying in a minute just spends another call on the
    // same wall. Everything else in the 429/5xx family is worth exactly one more try.
    const retryNow =
      !/usage_limit|quota/i.test(reason) && (RETRY_NOW.test(reason) || status >= 500 || status === 429);
    return { reason, detail, retryNow };
  }
  if (res.code !== 0) return { reason: `exit ${res.code}`, retryNow: false };
  return null;
}

/** One line for run.json and the Telegram error, naming the role and what the provider said. */
export function failureSummary(role: string, f: AgentFailure): string {
  return `${role}: ${f.reason}${f.detail ? ` (${f.detail})` : ""}`;
}

/**
 * runAgent, plus the failure classification, plus ONE retry when the failure is the momentary kind.
 * The caller gets `failure != null` for "this never produced a result" and can then refuse to treat the
 * missing artifact as an answer about the target. js-miners already had this shape (it walks a model
 * chain on a non-zero exit); the hunter, validator and reporter did not.
 */
export async function runAgentChecked(
  spec: AgentSpec,
  prompt: string,
  opts: { cwd: string; addDirs?: string[]; allowedTools?: string[]; timeoutMs?: number; outFile?: string },
  retry: { delayMs?: number } = {},
): Promise<{ res: CliResult; failure: AgentFailure | null }> {
  let res = await runAgent(spec, prompt, opts);
  let failure = agentFailure(res);
  if (failure?.retryNow) {
    const wait = retry.delayMs ?? Number(process.env.AGENT_RETRY_DELAY_MS ?? 30_000);
    warn(`[${spec.role}] ${failure.reason} -> one retry in ${Math.round(wait / 1000)}s`);
    await new Promise((r) => setTimeout(r, wait));
    res = await runAgent(spec, prompt, opts);
    failure = agentFailure(res);
  }
  if (failure) {
    warn(`[${spec.role}] produced NO result: ${failure.reason}${failure.detail ? ` (${failure.detail})` : ""}`);
  }
  return { res, failure };
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
