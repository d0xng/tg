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

// Map a model id to the CLI that runs it: deepseek-* via the claude CLI pointed at DeepSeek, glm-* via
// the claude CLI pointed at GLM's Coding Plan endpoint, gpt-* via codex, everything else (claude-*) via
// the claude CLI with the Max subscription.
export function providerForModel(model: string): Provider {
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
  // Escalation chain (weakest-first after the reverse in hunter.ts): hunter3 -> hunter2 -> hunter1.
  // The roster is model-id driven -- providerForModel routes each id, so a glm-* id runs on GLM's
  // Coding Plan automatically. To put GLM in the two lower rungs once a Coding-Plan key is live (a
  // general key 1113s), set HUNTER3_MODEL=glm-5.3-flash and HUNTER2_MODEL=glm-5.3 in .env and restart:
  // that is the intended cheapest->strongest ladder glm-5.3-flash -> glm-5.3 -> claude-opus-5 (the plan's
  // flagship is glm-5.3, its light model glm-5.3-flash; use plain ids, the "[1m]" alias is 1211 Unknown
  // on --model). Defaults stay on opus so a run never silently hunts with two dead (1113) rungs first.
  hunters: [
    { role: `hunter-${modelTag(process.env.HUNTER1_MODEL ?? "claude-opus-5")}`,  provider: providerForModel(process.env.HUNTER1_MODEL ?? "claude-opus-5"),  model: process.env.HUNTER1_MODEL ?? "claude-opus-5",  effort: EFFORT },
    { role: `hunter-${modelTag(process.env.HUNTER2_MODEL ?? "claude-opus-4-8")}`, provider: providerForModel(process.env.HUNTER2_MODEL ?? "claude-opus-4-8"), model: process.env.HUNTER2_MODEL ?? "claude-opus-4-8", effort: EFFORT },
    { role: `hunter-${modelTag(process.env.HUNTER3_MODEL ?? "claude-opus-4-6")}`, provider: providerForModel(process.env.HUNTER3_MODEL ?? "claude-opus-4-6"), model: process.env.HUNTER3_MODEL ?? "claude-opus-4-6", effort: EFFORT },
  ] as AgentSpec[],
  validator: {
    role: "validator",
    provider: "claude",
    model: process.env.VALIDATOR_MODEL ?? "claude-opus-4-8",
    effort: EFFORT,
  } as AgentSpec,
  reporter: {
    role: "reporter",
    provider: "claude",
    model: process.env.REPORTER_MODEL ?? "claude-opus-4-6",
    effort: EFFORT,
  } as AgentSpec,
  recon: {
    role: "recon",
    provider: "claude",
    model: process.env.RECON_MODEL ?? "claude-opus-4-6", // conversational front desk; override to a lighter model to cut chat cost
    effort: EFFORT,
  } as AgentSpec,
};

export const caps = {
  claudeConcurrency: Number(process.env.CLAUDE_CONCURRENCY ?? 2),
  codexConcurrency: Number(process.env.CODEX_CONCURRENCY ?? 1),
  hunterConcurrency: Number(process.env.HUNTER_CONCURRENCY ?? 3), // leads worked in parallel (each lead's model escalation stays sequential)
  subAgentsMax: Number(process.env.SUBAGENTS_MAX ?? 3),
};

export const timeouts = {
  crawlIdleMs: Number(process.env.CRAWL_IDLE_MS ?? 60_000), // stop crawl after this long with no new artifact
  crawlMaxMs: Number(process.env.CRAWL_MAX_MS ?? 3_600_000), // crawl hard safety ceiling (60 min)
  crawlMaxPages: Number(process.env.CRAWL_MAX_PAGES ?? 20000), // crawl page-visit safety cap
  jsAnalyzerMs: Number(process.env.JS_ANALYZER_TIMEOUT_MS ?? 1_800_000),
  hunterMs: Number(process.env.HUNTER_TIMEOUT_MS ?? 1_800_000),
};
