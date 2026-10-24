import { join } from "path";

// Project root = parent of src/.
export const ROOT = join(import.meta.dir, "..");
export const RUNS_DIR = process.env.HUNTLINE_RUNS ?? join(ROOT, "runs");
export const PROMPTS_DIR = join(ROOT, "prompts");

export type Provider = "codex" | "claude" | "deepseek" | "glm";
export type Effort = "low" | "medium" | "high" | "xhigh" | "max";
export const EFFORT_LEVELS: Effort[] = ["low", "medium", "high", "xhigh", "max"];

export interface AgentSpec {
  role: string;
  provider: Provider;
  model: string;
  /**
   * Reasoning effort, passed to the CLI as `--effort` (or codex's -c model_reasoning_effort). OPTIONAL
   * and absent means "do not pass the flag", which leaves the CLI's own default in charge. That is the
   * difference between asking for a level and not asking, and it is deliberate: measured on this rig,
   * low vs max is a 2 to 3 times swing in output tokens and latency on claude, GLM and DeepSeek alike,
   * while on a short reasoning task low was just as accurate as max. So only the hunters ask for a level.
   */
  effort?: Effort;
}

/**
 * The effort the HUNTERS run at, and only the hunters. Everything else deliberately sends no flag.
 *
 * Until now the `effort` field existed on every spec and was never read by cli.ts at all: the only thing
 * that reached a provider was codex's -c override. So every hunter, validator, reporter and miner this
 * pipeline has ever run went at the CLI's default, whatever EFFORT said.
 *
 * HUNTER_EFFORT (falling back to EFFORT, then xhigh) sets it. Set it to an empty value, or to
 * "default"/"off"/"none", and no flag is passed, which is how you go back to the previous behaviour
 * without touching code.
 */
function hunterEffort(): Effort | undefined {
  const raw = (process.env.HUNTER_EFFORT ?? process.env.EFFORT ?? "xhigh").trim().toLowerCase();
  if (!raw || /^(default|off|none)$/.test(raw)) return undefined;
  if (!(EFFORT_LEVELS as string[]).includes(raw)) {
    // console, not the log helper: config.ts is imported by everything and stays dependency-free.
    console.warn(`[config] HUNTER_EFFORT "${raw}" is not one of ${EFFORT_LEVELS.join("|")}; passing no effort flag`);
    return undefined;
  }
  return raw as Effort;
}
const HUNTER_EFFORT = hunterEffort();

export const telegram = {
  token: process.env.TELEGRAM_BOT_TOKEN ?? "",
  chatId: process.env.TELEGRAM_CHAT_ID ?? "",
};

export const chrome = {
  bin: process.env.CHROME_BIN ?? "google-chrome",
};

// Codex takes reasoning effort as a -c config override rather than a flag. Built per level now that the
// level is per spec instead of global, and only used when a spec actually asks for one. The exact key is
// verified in doctor.ts; keep it overridable so a wrong guess never silently breaks a run.
export function codexEffortConfig(effort: Effort): string {
  return process.env.CODEX_EFFORT_CONFIG ?? `model_reasoning_effort="${effort}"`;
}

// DeepSeek via its Anthropic-compatible endpoint, driven agentically through the Claude Code CLI.
export const deepseek = {
  apiKey: process.env.DEEPSEEK_API_KEY ?? "",
  baseUrl: process.env.DEEPSEEK_BASE_URL ?? "https://api.deepseek.com/anthropic",
};

// GLM (Zhipu / z.ai) via its Anthropic-compatible Coding Plan endpoint, driven agentically through the
// Claude Code CLI -- same pattern as DeepSeek. IMPORTANT: GLM_API_KEY must be a key generated from the
// GLM Coding Plan's own "API Keys" page. A general open-platform key returns 1113 "Insufficient balance
// or no resource package" on every paid model (only the free glm-4.5-flash answers), because a general
// key bills per-token while the Coding-Plan key draws on the flat subscription quota.
export const glm = {
  apiKey: process.env.GLM_API_KEY ?? "",
  baseUrl: process.env.GLM_BASE_URL ?? "https://api.z.ai/api/anthropic",
};

// A claude-* model id may carry an ACCOUNT TAG, e.g. "claude-opus-5-5@a", naming WHICH Claude
// subscription runs it, so two subscriptions can work in parallel on one box (each `claude` process
// takes its credential from its own environment). The tag resolves to the OAuth token in
// CLAUDE_OAUTH_<TAG>, minted once per account with `claude setup-token` (a one-year token, which also
// survives unattended runs better than a /login credential that can expire). An untagged id resolves to
// nothing here and keeps the box default CLAUDE_CODE_OAUTH_TOKEN, so existing rosters are unaffected.
// The tag is a claude-subscription convention only: glm-*/deepseek-*/gpt-* ids carry their own keys.
export function stripAccountTag(model: string): string {
  const at = model.indexOf("@");
  return at < 0 ? model : model.slice(0, at);
}

export function accountToken(model: string): string | undefined {
  const at = model.indexOf("@");
  if (at < 0) return undefined;
  const tag = model.slice(at + 1).toUpperCase();
  return process.env[`CLAUDE_OAUTH_${tag}`] || undefined;
}

// Map a model id to the CLI that runs it: deepseek-* via the claude CLI pointed at DeepSeek, glm-* via
// the claude CLI pointed at GLM's Coding Plan endpoint, gpt-* via codex, everything else (claude-*) via
// the claude CLI with the Max subscription. The account tag is stripped first so "claude-opus-5-5@a"
// still routes to the subscription CLI.
export function providerForModel(model: string): Provider {
  model = stripAccountTag(model);
  if (model.startsWith("deepseek")) return "deepseek";
  if (model.startsWith("glm")) return "glm";
  if (model.startsWith("gpt")) return "codex";
  return "claude";
}

// Short, filesystem-safe provenance tag for a model id, used in the hunter role (so the finding's
// "Confirmed by:" line and log filenames name the model that actually ran, even after a GLM flip).
// Must stay within [A-Za-z0-9.\-] to match dedupeFindings' filename regex.
export function modelTag(model: string): string {
  return model.replace(/^claude-/, "").replace(/[^A-Za-z0-9.\-]/g, "-");
}

/**
 * One hunter per lane that names a model. HUNTERn_MODEL unset keeps that lane's historical default;
 * set to an empty string, "off" or "none" and the lane is dropped, so the pipeline runs with however
 * many hunters are actually configured instead of always three.
 */
function hunterLanes(): AgentSpec[] {
  const defaults = ["claude-opus-5", "claude-opus-4-8", "claude-opus-4-6"];
  const out: AgentSpec[] = [];
  for (let i = 0; i < defaults.length; i++) {
    const raw = process.env[`HUNTER${i + 1}_MODEL`];
    const model = raw === undefined ? defaults[i]! : raw.trim();
    if (!model || /^(off|none|disabled)$/i.test(model)) continue;
    out.push({
      role: `hunter-${modelTag(model)}`,
      provider: providerForModel(model),
      model,
      effort: HUNTER_EFFORT,
    } as AgentSpec);
  }
  if (!out.length) {
    // Never leave the pipeline with nothing to hunt with: a run that reaches the hunting stage with an
    // empty roster would silently produce no verdicts at all.
    // console, not the log helper: config.ts is imported by everything and stays dependency-free.
    console.warn(`[config] every hunter lane is disabled; falling back to one hunter on ${defaults[0]}`);
    out.push({ role: `hunter-${modelTag(defaults[0]!)}`, provider: providerForModel(defaults[0]!), model: defaults[0]!, effort: HUNTER_EFFORT } as AgentSpec);
  }
  return out;
}

export const agents = {
  jsAnalyzer: {
    role: "js-analyzer",
    // Provider follows the model id, like every other spec. It used to be pinned to "deepseek", which
    // made the spec lie whenever JS_MODEL named another provider's model (e.g. JS_MODEL=glm-5.3-flash
    // sent a GLM id to DeepSeek and 400'd). runJsMiners overrides provider per chain entry, so the live
    // analyzing stage was unaffected, but anything using this spec directly got a confusing failure.
    provider: providerForModel(process.env.JS_MODEL ?? "deepseek-flash"),
    model: process.env.JS_MODEL ?? "deepseek-flash", // DeepSeek-V4.1-Flash by default (1M ctx)
    // No effort: the miners read JS and write leads, which is volume work rather than puzzle solving,
    // and raising the level only measurably raised tokens and latency.
  } as AgentSpec,
  // Leads are dealt round-robin across these hunters, one lead per hunter, each hunter in its own
  // parallel lane (see hunter.ts). The roster is model-id driven -- providerForModel routes each id, so a
  // glm-* id runs on GLM's Coding Plan automatically: e.g. HUNTER2_MODEL=glm-5.3 HUNTER3_MODEL=glm-5.3-flash
  // in .env, then restart. The key must be a Coding-Plan key (a general key 1113s); use plain ids, the
  // "[1m]" alias is 1211 Unknown on --model. Defaults stay on opus.
  // To run TWO Claude subscriptions side by side, append an account tag and set its token in .env:
  // HUNTER1_MODEL=claude-opus-5-5@a with CLAUDE_OAUTH_A=..., HUNTER2_MODEL=claude-opus-5-5@b with
  // CLAUDE_OAUTH_B=... . modelTag turns the "@" into "-", so the role (and every finding's provenance
  // line and log filename) names the account that ran it: hunter-opus-5-5-a.
  // A lane set to an EMPTY value (HUNTER3_MODEL= in .env), or to "off"/"none", runs no hunter at all.
  // That is the only way to hunt with fewer than three: the array used to be three literal entries, so
  // clearing HUNTER3_MODEL just fell through to its default and you still got three. Useful when one
  // provider's quota is spent and you want the lanes that remain to be the live ones.
  hunters: hunterLanes(),
  // validator/reporter/recon: like the hunters, the provider follows the model id, so e.g.
  // VALIDATOR_MODEL=glm-5.3-flash in .env runs it on GLM. Defaults stay on opus.
  validator: {
    role: "validator",
    provider: providerForModel(process.env.VALIDATOR_MODEL ?? "claude-opus-4-8"),
    model: process.env.VALIDATOR_MODEL ?? "claude-opus-4-8",
  } as AgentSpec,
  reporter: {
    role: "reporter",
    provider: providerForModel(process.env.REPORTER_MODEL ?? "claude-opus-4-6"),
    model: process.env.REPORTER_MODEL ?? "claude-opus-4-6",
  } as AgentSpec,
  recon: {
    role: "recon",
    provider: providerForModel(process.env.RECON_MODEL ?? "claude-opus-4-6"),
    model: process.env.RECON_MODEL ?? "claude-opus-4-6", // conversational front desk; override to a lighter model to cut chat cost
  } as AgentSpec,
};

export const caps = {
  claudeConcurrency: Number(process.env.CLAUDE_CONCURRENCY ?? 2),
  codexConcurrency: Number(process.env.CODEX_CONCURRENCY ?? 1),
  subAgentsMax: Number(process.env.SUBAGENTS_MAX ?? 3),
};

export const timeouts = {
  crawlIdleMs: Number(process.env.CRAWL_IDLE_MS ?? 60_000), // stop crawl after this long with no new artifact
  crawlMaxMs: Number(process.env.CRAWL_MAX_MS ?? 3_600_000), // crawl hard safety ceiling (60 min)
  crawlMaxPages: Number(process.env.CRAWL_MAX_PAGES ?? 20000), // crawl page-visit safety cap
  jsAnalyzerMs: Number(process.env.JS_ANALYZER_TIMEOUT_MS ?? 1_800_000),
  hunterMs: Number(process.env.HUNTER_TIMEOUT_MS ?? 1_800_000),
};
