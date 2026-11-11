// Telegram sink: plain text (no parse_mode, so record text can never be interpreted as markup).
// The bot token is part of the URL path, so no error ever carries the URL, the response body or
// Telegram's `description` (sinks/http.mjs): only the operation, status and numeric error_code.
import { request, jsonOf, SinkHttpError } from "./http.mjs";

export function telegramSink({ token, chatId, apiBase = "https://api.telegram.org" }) {
  if (!token || !chatId) throw new Error("telegram: token and chatId required");
  return {
    async send(text) {
      const r = await request("telegram sendMessage", `${apiBase}/bot${token}/sendMessage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          text: String(text).slice(0, 4000),
          disable_web_page_preview: true,
        }),
      });
      const j = jsonOf("telegram sendMessage", r);
      if (j?.ok !== true) {
        const code = Number.isSafeInteger(j?.error_code) ? ` error_code ${j.error_code}` : "";
        throw new SinkHttpError("telegram sendMessage", `ok=false${code}`);
      }
    },
  };
}
