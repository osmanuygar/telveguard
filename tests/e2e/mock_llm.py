"""
Uçtan uca test için sahte OpenAI uyumlu LLM (sadece stdlib).

Son kullanıcı mesajını olduğu gibi geri döndürür; böylece modelin ne gördüğü
(maskeli mi değil mi) cevaptan okunabilir. Model adı "fail-*" ise 502 HTML döner.
"""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        model = body.get("model", "")
        if model.startswith("fail-"):
            return self._send(502, b"<html>Bad Gateway</html>", "text/html")

        seen = [m.get("content") for m in body.get("messages", [])]
        completion = {
            "id": "mock-1", "object": "chat.completion", "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": f"MODEL GÖRDÜ: {seen[-1]}"}}],
            # Kaba token sayımı (kelime); Röntgen maliyet hesabı test edilebilsin
            "usage": {"prompt_tokens": sum(len(str(c).split()) for c in seen),
                      "completion_tokens": len(str(seen[-1]).split()) + 2},
            # Test betiği maskelemeyi doğrulayabilsin diye upstream'e giden ham mesajlar
            "mock_received_messages": seen,
        }
        self._send(200, json.dumps(completion, ensure_ascii=False).encode(), "application/json")

    def do_GET(self):
        self._send(200, b'{"status":"ok"}', "application/json")

    def _send(self, status, payload, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
