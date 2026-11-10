// Telegram sink: plain text (no parse_mode, so record text can never be interpreted as markup).
import { fetchWithTimeout, httpError } from "./http.mjs";

export function telegramSink({ token, chatId, apiBase = "https://api.telegram.org" }) {
  if (!token || !chatId) throw new Error("telegram: token and chatId required");
  return {
    async send(text) {
      const res = await fetchWithTimeout(`${apiBase}/bot${token}/sendMessage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          text: String(text).slice(0, 4000),
          disable_web_page_preview: true,
        }),
      });
      if (!res.ok) throw await httpError("telegram sendMessage", res);
      const j = await res.json();
      if (!j.ok) throw new Error(`telegram: ok=false ${j.description ?? ""}`);
    },
  };
}
