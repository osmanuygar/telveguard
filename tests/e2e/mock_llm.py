"""
Uçtan uca test için sahte LLM (sadece stdlib): OpenAI chat + responses, Anthropic messages.

Son kullanıcı mesajını olduğu gibi geri döndürür; böylece modelin ne gördüğü
(maskeli mi değil mi) cevaptan okunabilir. Model adı "fail-*" ise 502 HTML döner.
Mesaj "SIZINTI_TESTI" ile başlarsa girdide olmayan sahte bir AWS anahtarı "üretir"
(çıktı koruması testi; anahtar kaynakta parça parça durur).
Cevaplardaki "mock_received_*" alanları upstream'e ne gittiğini gösterir.
/webhook/<kanal> Slack / Teams bildirimlerini kaydeder; GET /webhook/received son 100'ünü döner.
"stream": true ise cevap 4 karakterlik delta'larla, olaylar arasında 20 ms beklenerek SSE olarak akar
(artımlı streaming testi; usage biçimin kendi yerinde).
/bitbucket/... Bitbucket Data Center taklidi (politika Git yansıtma): SEC/telveguard-config deposu,
bellekte; commit / PR bağlantıları tarayıcıda düz metin olarak açılır.
"""
import json
import time
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_KEY = "AKIA" + "Q3EXAMPLE7ABCDEF"
WEBHOOKS = []  # [{"channel": ..., "body": ...}]
BB_API = "/bitbucket/rest/api/1.0/projects/SEC/repos/telveguard-config"
BB_WEB = "/bitbucket/projects/SEC/repos/telveguard-config"
BB = {"branches": {"main": {}}, "commits": {}, "prs": []}   # dal -> yol -> (commit, içerik)


def _texts(content):
    if isinstance(content, str):
        return content
    out = []
    for b in content or []:
        if isinstance(b, dict):
            out.append(b.get("text") or (b.get("content") if isinstance(b.get("content"), str) else "")
                       or b.get("output", ""))
    return " ".join(x for x in out if x)


def _pieces(text, n=4):
    return [text[i:i + n] for i in range(0, len(text), n)] or [""]


def _chat_events(resp, body):
    base = {k: resp[k] for k in ("id", "created", "model")}
    base["object"] = "chat.completion.chunk"
    yield None, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}
    for p in _pieces(resp["choices"][0]["message"]["content"]):
        yield None, {**base, "choices": [{"index": 0, "delta": {"content": p}, "finish_reason": None}]}
    yield None, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
    if (body.get("stream_options") or {}).get("include_usage"):
        yield None, {**base, "choices": [], "usage": resp["usage"]}
    yield None, "[DONE]"


def _anthropic_events(resp):
    start = {**resp, "content": [], "stop_reason": None, "usage": {**resp["usage"], "output_tokens": 1}}
    yield "message_start", {"type": "message_start", "message": start}
    yield "content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
    for p in _pieces(resp["content"][0]["text"]):
        yield "content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}}
    yield "content_block_stop", {"type": "content_block_stop", "index": 0}
    yield "message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                            "usage": {"output_tokens": resp["usage"]["output_tokens"]}}
    yield "message_stop", {"type": "message_stop"}


def _responses_events(resp):
    seq = iter(range(10_000))

    def ev(d):
        return d["type"], {**d, "sequence_number": next(seq)}
    item = resp["output"][0]
    text = item["content"][0]["text"]
    yield ev({"type": "response.created", "response": {**resp, "status": "in_progress", "output": [], "usage": None}})
    yield ev({"type": "response.output_item.added", "output_index": 0, "item": {**item, "content": [], "status": "in_progress"}})
    loc = {"item_id": item["id"], "output_index": 0, "content_index": 0}
    yield ev({"type": "response.content_part.added", **loc, "part": {"type": "output_text", "text": "", "annotations": []}})
    for p in _pieces(text):
        yield ev({"type": "response.output_text.delta", **loc, "delta": p, "logprobs": []})
    yield ev({"type": "response.output_text.done", **loc, "text": text, "logprobs": []})
    yield ev({"type": "response.content_part.done", **loc, "part": item["content"][0]})
    yield ev({"type": "response.output_item.done", "output_index": 0, "item": item})
    yield ev({"type": "response.completed", "response": resp})


def _answer(last):
    return ("Örnek yapılandırma: key=" + FAKE_KEY) if str(last).startswith("SIZINTI_TESTI") \
        else f"MODEL GÖRDÜ: {last}"


class Handler(BaseHTTPRequestHandler):
    # ---------------- Bitbucket DC taklidi ----------------
    def _bb(self, method):
        from urllib.parse import parse_qs, unquote, urlsplit
        url = urlsplit(self.path)
        path, q = unquote(url.path), {k: v[0] for k, v in parse_qs(url.query).items()}
        if path.startswith(BB_WEB):   # tarayıcıda commit / PR: düz metin
            ref = path.rsplit("/", 1)[-1]
            c = BB["commits"].get(ref) or (BB["prs"][int(ref) - 1] if ref.isdigit() and int(ref) <= len(BB["prs"]) else None)
            return self._send(200 if c else 404, (json.dumps(c, ensure_ascii=False, indent=2) if c and "fromRef" in c
                              else f"{c['message']}\n\n----- {c['path']} -----\n{c['content']}" if c else "yok").encode(),
                              "text/plain; charset=utf-8")
        if not self.headers.get("Authorization", "").startswith("Bearer "):
            return self._json({"errors": [{"message": "Authentication required"}]}, 401)
        sub = path[len(BB_API):]
        if method == "GET" and sub == "":
            return self._json({"name": "telveguard-config", "slug": "telveguard-config"})
        if method == "GET" and sub == "/branches":
            return self._json({"values": [{"displayId": b} for b in BB["branches"] if q.get("filterText", "") in b]})
        if method == "GET" and sub == "/commits":
            branch = q["until"].removeprefix("refs/heads/")
            if branch not in BB["branches"]:
                return self._json({"errors": [{"message": "branch yok"}]}, 404)
            f = BB["branches"][branch].get(q["path"])
            return self._json({"values": [{"id": f[0]}] if f else []})
        if method == "PUT" and sub.startswith("/browse/"):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            msg = BytesParser(policy=HTTP).parsebytes(b"content-type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + raw)
            form = {pt.get_param("name", header="content-disposition"): pt.get_payload(decode=True).decode() for pt in msg.iter_parts()}
            fpath, branch = sub[len("/browse/"):], form["branch"]
            if branch not in BB["branches"]:
                BB["branches"][branch] = dict(BB["branches"][form["sourceBranch"]])
            cur = BB["branches"][branch].get(fpath)
            if cur and form.get("sourceCommitId") != cur[0]:
                return self._json({"errors": [{"message": "dosya değişmiş"}]}, 409)
            cid = f"{len(BB['commits']) + 1:040x}"
            BB["commits"][cid] = {"message": form["message"], "path": fpath, "content": form["content"], "branch": branch}
            BB["branches"][branch][fpath] = (cid, form["content"])
            return self._json({"id": cid})
        if method == "POST" and sub == "/pull-requests":
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            BB["prs"].append(body)
            n = len(BB["prs"])
            return self._json({"id": n, "links": {"self": [{"href": f"http://localhost:9000{BB_WEB}/pull-requests/{n}"}]}}, 201)
        return self._json({"errors": [{"message": f"{method} {sub}"}]}, 404)

    def do_PUT(self):
        if self.path.startswith("/bitbucket/"):
            return self._bb("PUT")
        self._send(405, b"", "text/plain")

    def do_POST(self):
        if self.path.startswith("/bitbucket/"):
            return self._bb("POST")
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.startswith("/webhook/"):
            WEBHOOKS.append({"channel": self.path.rsplit("/", 1)[-1], "body": body})
            del WEBHOOKS[:-100]
            return self._json({"ok": True})
        model = body.get("model", "")
        if model.startswith("fail-"):
            return self._send(502, b"<html>Bad Gateway</html>", "text/html")
        if self.path.endswith("/count_tokens"):
            return self._json({"input_tokens": len(json.dumps(body).split())})
        if self.path.endswith("/v1/messages"):
            resp = self._anthropic(body, model)
            return self._sse(_anthropic_events(resp)) if body.get("stream") else self._json(resp)
        if self.path.endswith("/embeddings"):
            return self._json(self._embeddings(body, model))
        if self.path.endswith("/responses"):
            resp = self._responses(body, model)
            return self._sse(_responses_events(resp)) if body.get("stream") else self._json(resp)
        resp = self._chat(body, model)
        return self._sse(_chat_events(resp, body)) if body.get("stream") else self._json(resp)

    def _sse(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        for event, data in events:
            head = f"event: {event}\n" if event else ""
            body = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
            self.wfile.write(f"{head}data: {body}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.02)
        self.close_connection = True

    def _chat(self, body, model):
        seen = [m.get("content") for m in body.get("messages", [])]
        return {
            "id": "mock-1", "object": "chat.completion", "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": _answer(seen[-1])}}],
            # Kaba token sayımı (kelime); Röntgen maliyet hesabı test edilebilsin
            "usage": {"prompt_tokens": sum(len(str(c).split()) for c in seen),
                      "completion_tokens": len(str(seen[-1]).split()) + 2},
            # Test betiği maskelemeyi doğrulayabilsin diye upstream'e giden ham mesajlar
            "mock_received_messages": seen,
        }

    def _anthropic(self, body, model):
        last = _texts(body["messages"][-1].get("content"))
        return {"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
                "content": [{"type": "text", "text": _answer(last)}], "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": len(json.dumps(body).split()), "output_tokens": 5},
                "mock_received_system": body.get("system"), "mock_received_last": last}

    def _embeddings(self, body, model):
        inp = body["input"] if isinstance(body["input"], list) else [body["input"]]
        return {"object": "list", "model": model,
                "data": [{"object": "embedding", "index": i, "embedding": [0.1, 0.2, 0.3]} for i in range(len(inp))],
                "usage": {"prompt_tokens": sum(len(str(x).split()) for x in inp),
                          "total_tokens": sum(len(str(x).split()) for x in inp)},
                "mock_received_input": body["input"], "mock_received_keys": sorted(body)}

    def _responses(self, body, model):
        inp = body.get("input")
        last = inp if isinstance(inp, str) else _texts(inp[-1].get("content")) or inp[-1].get("output", "")
        return {"id": "resp_mock", "object": "response", "created_at": int(time.time()), "model": model,
                "status": "completed", "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
                "output": [{"type": "message", "id": "msg_mock", "role": "assistant", "status": "completed",
                            "content": [{"type": "output_text", "text": _answer(last), "annotations": []}]}],
                "usage": {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 5,
                          "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 15},
                "mock_received_instructions": body.get("instructions"), "mock_received_last": last}

    def do_GET(self):
        if self.path.startswith("/bitbucket/"):
            return self._bb("GET")
        if self.path.startswith("/webhook/received"):
            return self._json(WEBHOOKS)
        self._send(200, b'{"status":"ok"}', "application/json")

    def _json(self, obj, status=200):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

    def _send(self, status, payload, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
