import { telegram } from "./config.ts";
import { log, warn } from "./log.ts";

const api = (method: string) => `https://api.telegram.org/bot${telegram.token}/${method}`;

// Notify d0x. No-op (logs only) when no token is configured, so the pipeline runs headless in dev.
export async function notify(text: string): Promise<void> {
  log("NOTIFY:", text);
  if (!telegram.token || !telegram.chatId) return;
  try {
    await fetch(api("sendMessage"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: telegram.chatId, text, disable_web_page_preview: true }),
    });
  } catch (e) {
    warn("telegram notify failed:", String(e));
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

// Long-poll getUpdates and hand each new text message to the callback. One target at a time for now.
export async function pollUpdates(onHunt: (req: HuntRequest) => Promise<void>): Promise<void> {
  if (!telegram.token) {
    warn("TELEGRAM_BOT_TOKEN not set; Telegram ingress disabled. Use `bun run hunt <domain>` instead.");
    return;
  }
  let offset = 0;
  log("telegram ingress up; send a domain + scope to start a run");
  for (;;) {
    try {
      const res = await fetch(api("getUpdates") + `?timeout=50&offset=${offset}`);
      const data = (await res.json()) as any;
      for (const u of data.result ?? []) {
        offset = u.update_id + 1;
        const msg = u.message?.text;
        if (!msg) continue;
        const req = parseHuntMessage(msg);
        if (!req) {
          await notify("send me a domain to hunt, e.g.\nexample.com\nscope: *.example.com (authorized)");
          continue;
        }
        await notify(`starting run on ${req.domain}`);
        try {
          await onHunt(req);
        } catch (e) {
          await notify(`run failed on ${req.domain}: ${String(e)}`);
        }
      }
    } catch (e) {
      warn("getUpdates failed, retrying:", String(e));
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}
