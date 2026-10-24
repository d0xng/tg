import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { telegram, RUNS_DIR } from "./config.ts";
import { log, warn } from "./log.ts";

const api = (method: string) => `https://api.telegram.org/bot${telegram.token}/${method}`;

// Every Telegram call here is AWAITED at a stage boundary, so one that never returns stalls the whole
// run: a notify between hunting and done held a run silent for 20 minutes until the watchdog declared
// it dead and killed it. fetch has no default timeout, so each call carries its own. getUpdates is the
// deliberate exception -- it is a 50s long poll, so its budget sits above that or the ingress would
// abort on every quiet cycle. A timeout lands in the existing catch: it warns and the run continues.
const MSG_TIMEOUT_MS = Number(process.env.TELEGRAM_MSG_TIMEOUT_MS ?? 20_000);
const DOC_TIMEOUT_MS = Number(process.env.TELEGRAM_DOC_TIMEOUT_MS ?? 60_000);
const POLL_TIMEOUT_MS = Number(process.env.TELEGRAM_POLL_TIMEOUT_MS ?? 70_000);

// MarkdownV2 escaping: every one of these is reserved and must be backslash-escaped in dynamic text.
// We compose messages from static labels (where we intend *bold*) plus escaped dynamic values.
export function mdEscape(s: string): string {
  return String(s).replace(/[_*\[\]()~`>#+\-=|{}.!\\]/g, "\\$&");
}

// Plain notify (no formatting). No-op (logs only) when no token/chat is configured.
export async function notify(text: string): Promise<void> {
  log("NOTIFY:", text);
  if (!telegram.token || !telegram.chatId) return;
  try {
    await fetch(api("sendMessage"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: telegram.chatId, text, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(MSG_TIMEOUT_MS),
    });
  } catch (e) {
    warn("telegram notify failed:", String(e));
  }
}

// Markdown (MarkdownV2) notify. Caller passes text already composed with intended *bold* markers and
// dynamic values run through mdEscape(). Falls back to plain send if Telegram rejects the markup.
export async function notifyMd(text: string): Promise<void> {
  log("NOTIFY:", text.replace(/\\([_*\[\]()~`>#+\-=|{}.!\\])/g, "$1"));
  if (!telegram.token || !telegram.chatId) return;
  try {
    const res = await fetch(api("sendMessage"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: telegram.chatId,
        text,
        parse_mode: "MarkdownV2",
        disable_web_page_preview: true,
      }),
      signal: AbortSignal.timeout(MSG_TIMEOUT_MS),
    });
    if (!res.ok) {
      // markup rejected -> resend as plain so the message still arrives
      const plain = text.replace(/\\([_*\[\]()~`>#+\-=|{}.!\\])/g, "$1").replace(/[*_`]/g, "");
      await notify(plain);
    }
  } catch (e) {
    warn("telegram notifyMd failed:", String(e));
  }
}

// Send a file (e.g. a leads list or a finished report) as a Telegram document, so the .md arrives
// intact with no markup-escaping limits. caption is optional MarkdownV2.
export async function sendDocument(filename: string, content: string, caption?: string): Promise<void> {
  log("SEND DOC:", filename, `(${content.length} bytes)`);
  if (!telegram.token || !telegram.chatId) return;
  try {
    const form = new FormData();
    form.append("chat_id", String(telegram.chatId));
    form.append("document", new Blob([content], { type: "text/markdown" }), filename);
    if (caption) {
      form.append("caption", caption);
      form.append("parse_mode", "MarkdownV2");
    }
    const res = await fetch(api("sendDocument"), {
      method: "POST",
      body: form,
      signal: AbortSignal.timeout(DOC_TIMEOUT_MS),
    });
    if (!res.ok) warn("telegram sendDocument failed:", res.status, await res.text().catch(() => ""));
  } catch (e) {
    warn("telegram sendDocument failed:", String(e));
  }
}

export interface HuntRequest {
  domain: string;
  scope: string;
}

// A Telegram message starts a run. First token of the first line is the target; the whole message
// body is kept as scope. Forgiving on purpose: no rigid command syntax to trip over.
export function parseHuntMessage(text: string): HuntRequest | null {
  const body = text.trim();
  if (!body) return null;
  const firstLine = body.split("\n")[0].trim().replace(/^\/hunt\s+/i, "");
  const domain = firstLine.split(/\s+/)[0];
  if (!domain || !/[.]/.test(domain)) return null;
  return { domain, scope: body };
}

// Long-poll getUpdates and hand each new text message to the callback. The callback is the recon
// agent (conversational + scope expansion); legacy parseHuntMessage stays exported for the simple path.
export async function pollUpdates(onMessage: (text: string, chatId: number) => Promise<void>): Promise<void> {
  if (!telegram.token) {
    warn("TELEGRAM_BOT_TOKEN not set; Telegram ingress disabled. Use `bun run hunt <domain>` instead.");
    return;
  }
  // Persist the update offset to disk so a serve restart does NOT re-deliver (and re-run) old messages.
  const OFFSET_FILE = join(RUNS_DIR, ".telegram-offset");
  let offset = 0;
  try {
    offset = Number(readFileSync(OFFSET_FILE, "utf8").trim()) || 0;
  } catch {
    /* first run, no offset yet */
  }
  log(`telegram ingress up (offset ${offset}); talk to the bot to start`);
  for (;;) {
    try {
      const res = await fetch(api("getUpdates") + `?timeout=50&offset=${offset}`, {
        signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
      });
      const data = (await res.json()) as any;
      for (const u of data.result ?? []) {
        offset = u.update_id + 1;
        try {
          writeFileSync(OFFSET_FILE, String(offset)); // ack before processing so a crash/restart never replays it
        } catch {
          /* best effort */
        }
        const msg = u.message?.text;
        const chatId = u.message?.chat?.id;
        if (!msg || chatId == null) continue;
        try {
          await onMessage(msg, chatId);
        } catch (e) {
          warn("onMessage failed:", String(e));
        }
      }
    } catch (e) {
      warn("getUpdates failed, retrying:", String(e));
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}
