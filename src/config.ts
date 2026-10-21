import { join } from "path";

// Project root = parent of src/.
export const ROOT = join(import.meta.dir, "..");
export const RUNS_DIR = process.env.HUNTLINE_RUNS ?? join(ROOT, "runs");
export const PROMPTS_DIR = join(ROOT, "prompts");

export type Provider = "codex" | "claude" | "deepseek" | "glm";
export type Effort = "low" | "medium" | "high" | "xhigh";

export interface AgentSpec {
  role: string;
  provider: Provider;
  model: string;
  effort: Effort;
}

const EFFORT = (process.env.EFFORT as Effort) ?? "xhigh";

export const telegram = {
  token: process.env.TELEGRAM_BOT_TOKEN ?? "",
  chatId: process.env.TELEGRAM_CHAT_ID ?? "",
};

export const chrome = {
  bin: process.env.CHROME_BIN ?? "google-chrome",
};

// Codex takes reasoning effort as a -c config override. The exact key is verified in doctor.ts;
// keep it overridable so a wrong guess never silently breaks a run.
export const codexEffortConfig =
  process.env.CODEX_EFFORT_CONFIG ?? `model_reasoning_effort="${EFFORT}"`;

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

export const agents = {
  jsAnalyzer: {
    role: "js-analyzer",
    provider: "deepseek",
    model: process.env.JS_MODEL ?? "deepseek-flash", // DeepSeek-V4.1-Flash, PRIMARY analyzer (1M ctx, no OpenAI cyber classifier)
    effort: "high",
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
  hunters: [
    { role: `hunter-${modelTag(process.env.HUNTER1_MODEL ?? "claude-opus-5")}`,  provider: providerForModel(process.env.HUNTER1_MODEL ?? "claude-opus-5"),  model: process.env.HUNTER1_MODEL ?? "claude-opus-5",  effort: EFFORT },
    { role: `hunter-${modelTag(process.env.HUNTER2_MODEL ?? "claude-opus-4-8")}`, provider: providerForModel(process.env.HUNTER2_MODEL ?? "claude-opus-4-8"), model: process.env.HUNTER2_MODEL ?? "claude-opus-4-8", effort: EFFORT },
    { role: `hunter-${modelTag(process.env.HUNTER3_MODEL ?? "claude-opus-4-6")}`, provider: providerForModel(process.env.HUNTER3_MODEL ?? "claude-opus-4-6"), model: process.env.HUNTER3_MODEL ?? "claude-opus-4-6", effort: EFFORT },
  ] as AgentSpec[],
  // validator/reporter/recon: like the hunters, the provider follows the model id, so e.g.
  // VALIDATOR_MODEL=glm-5.3-flash in .env runs it on GLM. Defaults stay on opus.
  validator: {
    role: "validator",
    provider: providerForModel(process.env.VALIDATOR_MODEL ?? "claude-opus-4-8"),
    model: process.env.VALIDATOR_MODEL ?? "claude-opus-4-8",
    effort: EFFORT,
  } as AgentSpec,
  reporter: {
    role: "reporter",
    provider: providerForModel(process.env.REPORTER_MODEL ?? "claude-opus-4-6"),
    model: process.env.REPORTER_MODEL ?? "claude-opus-4-6",
    effort: EFFORT,
  } as AgentSpec,
  recon: {
    role: "recon",
    provider: providerForModel(process.env.RECON_MODEL ?? "claude-opus-4-6"),
    model: process.env.RECON_MODEL ?? "claude-opus-4-6", // conversational front desk; override to a lighter model to cut chat cost
    effort: EFFORT,
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
