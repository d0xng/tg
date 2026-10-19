import { join } from "path";

// Project root = parent of src/.
export const ROOT = join(import.meta.dir, "..");
export const RUNS_DIR = process.env.HUNTLINE_RUNS ?? join(ROOT, "runs");
export const PROMPTS_DIR = join(ROOT, "prompts");

export type Provider = "codex" | "claude" | "deepseek";
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

// Map a model id to the CLI that runs it: deepseek-* via the claude CLI pointed at DeepSeek, gpt-*
// via codex, everything else (claude-*) via the claude CLI with the Max subscription.
export function providerForModel(model: string): Provider {
  if (model.startsWith("deepseek")) return "deepseek";
  if (model.startsWith("gpt")) return "codex";
  return "claude";
}

export const agents = {
  jsAnalyzer: {
    role: "js-analyzer",
    provider: "deepseek",
    model: process.env.JS_MODEL ?? "deepseek-flash", // DeepSeek-V4.1-Flash, PRIMARY analyzer (1M ctx, no OpenAI cyber classifier)
    effort: "high",
  } as AgentSpec,
  hunters: [
    { role: "hunter-opus5",  provider: "claude", model: process.env.HUNTER1_MODEL ?? "claude-opus-5", effort: EFFORT },
    { role: "hunter-opus48", provider: "claude", model: process.env.HUNTER2_MODEL ?? "claude-opus-4-8", effort: EFFORT },
    { role: "hunter-deepseek", provider: "deepseek", model: process.env.HUNTER3_MODEL ?? "deepseek-flash", effort: "high" }, // replaces opus-4.6
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
  subAgentsMax: Number(process.env.SUBAGENTS_MAX ?? 3),
};

export const timeouts = {
  crawlIdleMs: Number(process.env.CRAWL_IDLE_MS ?? 60_000), // stop crawl after this long with no new artifact
  crawlMaxMs: Number(process.env.CRAWL_MAX_MS ?? 3_600_000), // crawl hard safety ceiling (60 min)
  crawlMaxPages: Number(process.env.CRAWL_MAX_PAGES ?? 20000), // crawl page-visit safety cap
  jsAnalyzerMs: Number(process.env.JS_ANALYZER_TIMEOUT_MS ?? 1_800_000),
  hunterMs: Number(process.env.HUNTER_TIMEOUT_MS ?? 1_800_000),
};
