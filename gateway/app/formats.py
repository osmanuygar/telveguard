"""
Desteklenen istemci API biçimleri. Koruma akışı (kimlik -> tarama -> politika -> maskeleme ->
upstream -> çıktı koruması -> denetim) tektir; biçimler yalnızca şunları tanımlar:
metin nerede, upstream nereye, token kullanımı nasıl okunur, hata ve stream nasıl görünür.

  chat      OpenAI  POST /v1/chat/completions   (OpenAI SDK, LangChain, Open WebUI, ...)
  responses OpenAI  POST /v1/responses          (OpenAI Responses API, Codex CLI)
  messages  Anthropic POST /v1/messages         (Claude SDK, Claude Code)

Format çevirisi YOKTUR: her biçim kendi türündeki upstream'e gider.

"Part": maskelenecek / taranacak tek bir metin parçası (okuyucu + yazıcı + rol). Araç
argümanları JSON ise ayrıştırılıp YAPRAK string'ler ayrı parça olur: maskeli bir private key
geri açılırken satır sonları JSON'u bozmasın. Anthropic "thinking" blokları imzalıdır;
içeriği değişirse sonraki turda API reddeder, bu yüzden dokunulmaz.
"""
import json
import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple

from fastapi.responses import JSONResponse

# OpenAI uyumlu upstream'ler (taban adres /v1 içerir)
UPSTREAMS = {
    "internal": os.getenv("UPSTREAM_INTERNAL_URL", "http://vllm:8000/v1"),
    "external": os.getenv("UPSTREAM_EXTERNAL_URL", "https://api.openai.com/v1"),
}
UPSTREAM_KEYS = {
    "internal": os.getenv("UPSTREAM_INTERNAL_KEY", ""),
    "external": os.getenv("UPSTREAM_EXTERNAL_KEY", ""),
}
# Anthropic upstream'leri (taban adres /v1 içermez). Kurum içi: Anthropic uyumlu bir sunucu
# (ör. /v1/messages destekleyen vLLM) varsa; yoksa kurum içi hedefe Anthropic biçimi gönderilemez.
ANTHROPIC_UPSTREAMS = {
    "external": os.getenv("UPSTREAM_ANTHROPIC_URL", "https://api.anthropic.com"),
    "internal": os.getenv("UPSTREAM_ANTHROPIC_INTERNAL_URL", ""),
}
ANTHROPIC_KEYS = {
    "external": os.getenv("UPSTREAM_ANTHROPIC_KEY", ""),
    "internal": os.getenv("UPSTREAM_ANTHROPIC_INTERNAL_KEY", ""),
}
ANTHROPIC_VERSION = "2023-06-01"


@dataclass
class Part:
    get: Callable[[], str]
    set: Callable[[str], None]
    role: str   # system | user | assistant | tool

    @property
    def text(self) -> str:
        return self.get()


def _key(container: Any, key: Any, role: str) -> Part:
    def _set(value: str) -> None:
        container[key] = value
    return Part(lambda: container[key], _set, role)


def _leaves(obj: Any, role: str, on_change: Callable[[], None] = lambda: None) -> List[Part]:
    """İç içe dict / list içindeki tüm string yapraklar (araç argümanları)."""
    parts: List[Part] = []
    items = obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else []
    for k, v in items:
        if isinstance(v, str):
            def _set(value: str, c=obj, key=k) -> None:
                c[key] = value
                on_change()
            parts.append(Part(lambda c=obj, key=k: c[key], _set, role))
        elif isinstance(v, (dict, list)):
            parts.extend(_leaves(v, role, on_change))
    return parts


def _json_string(container: Any, key: Any, role: str) -> List[Part]:
    """JSON metni tutan alan (OpenAI araç argümanları): ayrıştırılabilirse yapraklar,
    değişiklikte yeniden serileştirilir; ayrıştırılamazsa düz metin olarak ele alınır."""
    raw = container.get(key) if isinstance(container, dict) else None
    if not isinstance(raw, str):
        return []
    try:
        obj = json.loads(raw)
    except ValueError:
        return [_key(container, key, role)]
    if not isinstance(obj, (dict, list)):
        return [_key(container, key, role)]

    def _dump() -> None:
        container[key] = json.dumps(obj, ensure_ascii=False)
    return _leaves(obj, role, _dump)


def _sse(event: Optional[str], data: dict) -> bytes:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {json.dumps(data, ensure_ascii=False)}\n\n".encode()


class ApiFormat:
    name = ""
    injection_roles = {"user", "tool"}  # system / assistant uygulamanın kendi metni sayılır

    def validate(self, body: Dict[str, Any]) -> Optional[str]:
        raise NotImplementedError

    def request_parts(self, body: Dict[str, Any]) -> List[Part]:
        raise NotImplementedError

    def response_parts(self, resp: Dict[str, Any]) -> List[Part]:
        raise NotImplementedError

    def upstream(self, destination: str, headers) -> Optional[Tuple[str, Dict[str, str]]]:
        raise NotImplementedError

    def usage(self, resp: Optional[Dict[str, Any]]) -> Tuple[int, int, float, bool]:
        """(girdi token, çıktı token, maliyet için etkin girdi token, usage biliniyor mu)"""
        raise NotImplementedError

    def error(self, status: int, message: str, code: str, type_: str = "") -> JSONResponse:
        return JSONResponse(status_code=status, content={
            "error": {"message": message, "type": type_ or "telveguard_policy_violation", "code": code}})

    def buffered_sse(self, resp: Dict[str, Any]) -> AsyncIterator[bytes]:
        raise NotImplementedError


class OpenAIChat(ApiFormat):
    name = "chat"

    def validate(self, body):
        if not isinstance(body.get("messages", []), list):
            return "Gövde bir nesne, 'messages' bir liste olmalı."
        return None

    def request_parts(self, body):
        parts: List[Part] = []
        for msg in body.get("messages", []):
            if not isinstance(msg, dict):
                continue
            role = "tool" if msg.get("role") in ("tool", "function") else msg.get("role", "user")
            content = msg.get("content")
            if isinstance(content, str):
                parts.append(_key(msg, "content", role))
            elif isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str):
                        parts.append(_key(p, "text", role))
            for call in msg.get("tool_calls") or []:
                parts.extend(_json_string(call.get("function") or {}, "arguments", role))
        return parts

    def response_parts(self, resp):
        parts: List[Part] = []
        for choice in resp.get("choices", []):
            msg = choice.get("message") or {}
            if isinstance(msg.get("content"), str):
                parts.append(_key(msg, "content", "assistant"))
            for call in msg.get("tool_calls") or []:
                parts.extend(_json_string(call.get("function") or {}, "arguments", "assistant"))
        return parts

    def upstream(self, destination, headers):
        h = {"Content-Type": "application/json"}
        if UPSTREAM_KEYS[destination]:
            h["Authorization"] = f"Bearer {UPSTREAM_KEYS[destination]}"
        return f"{UPSTREAMS[destination]}/chat/completions", h

    def usage(self, resp):
        u = (resp or {}).get("usage") or {}
        pt, ct = int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)
        return pt, ct, pt, bool(u)

    async def buffered_sse(self, resp):
        """Tamponlanmış cevabı stream biçiminde döndürür (tüm seçenekler + araç çağrıları)."""
        base = {"id": resp.get("id"), "object": "chat.completion.chunk",
                "created": resp.get("created"), "model": resp.get("model")}
        for choice in resp.get("choices", []):
            msg = choice.get("message") or {}
            delta: Dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
            if msg.get("tool_calls"):
                delta["tool_calls"] = [{"index": i, **call} for i, call in enumerate(msg["tool_calls"])]
            yield _sse(None, {**base, "choices": [{"index": choice.get("index", 0), "delta": delta,
                                                   "finish_reason": choice.get("finish_reason")}]})
        yield b"data: [DONE]\n\n"


class OpenAIResponses(OpenAIChat):
    name = "responses"

    def validate(self, body):
        if not isinstance(body.get("input"), (str, list)):
            return "'input' bir metin ya da liste olmalı."
        return None

    def request_parts(self, body):
        parts: List[Part] = []
        if isinstance(body.get("instructions"), str):
            parts.append(_key(body, "instructions", "system"))
        if isinstance(body.get("input"), str):
            parts.append(_key(body, "input", "user"))
            return parts
        for item in body.get("input") or []:
            if not isinstance(item, dict):
                continue
            kind = item.get("type", "message")
            if kind == "message" or "role" in item:
                role = item.get("role", "user")
                role = "system" if role == "developer" else role
                content = item.get("content")
                if isinstance(content, str):
                    parts.append(_key(item, "content", role))
                elif isinstance(content, list):
                    for p in content:
                        if isinstance(p, dict) and p.get("type") in ("input_text", "output_text", "text") \
                                and isinstance(p.get("text"), str):
                            parts.append(_key(p, "text", role))
            elif kind == "function_call":
                parts.extend(_json_string(item, "arguments", "assistant"))
            elif kind == "function_call_output":
                if isinstance(item.get("output"), str):
                    parts.append(_key(item, "output", "tool"))
                elif isinstance(item.get("output"), list):
                    parts.extend(_leaves(item["output"], "tool"))
            # reasoning vb.: dokunulmaz
        return parts

    def response_parts(self, resp):
        parts: List[Part] = []
        for item in resp.get("output", []):
            if item.get("type") == "message":
                for p in item.get("content") or []:
                    if p.get("type") == "output_text" and isinstance(p.get("text"), str):
                        parts.append(_key(p, "text", "assistant"))
            elif item.get("type") == "function_call":
                parts.extend(_json_string(item, "arguments", "assistant"))
        return parts

    def upstream(self, destination, headers):
        url, h = super().upstream(destination, headers)
        return url.rsplit("/chat/completions", 1)[0] + "/responses", h

    def usage(self, resp):
        u = (resp or {}).get("usage") or {}
        pt, ct = int(u.get("input_tokens") or 0), int(u.get("output_tokens") or 0)
        return pt, ct, pt, bool(u)

    async def buffered_sse(self, resp):
        seq = 0

        def ev(data: dict) -> bytes:
            nonlocal seq
            data = {**data, "sequence_number": seq}
            seq += 1
            return _sse(data["type"], data)

        pending = {**resp, "status": "in_progress", "output": [], "usage": None}
        yield ev({"type": "response.created", "response": pending})
        yield ev({"type": "response.in_progress", "response": pending})
        for oi, item in enumerate(resp.get("output", [])):
            item_id = item.get("id") or f"item_{oi}"
            if item.get("type") == "message":
                yield ev({"type": "response.output_item.added", "output_index": oi,
                          "item": {**item, "content": [], "status": "in_progress"}})
                for ci, part in enumerate(item.get("content") or []):
                    loc = {"item_id": item_id, "output_index": oi, "content_index": ci}
                    if part.get("type") == "output_text":
                        yield ev({"type": "response.content_part.added", **loc,
                                  "part": {**part, "text": "", "annotations": []}})
                        yield ev({"type": "response.output_text.delta", **loc, "delta": part["text"], "logprobs": []})
                        yield ev({"type": "response.output_text.done", **loc, "text": part["text"], "logprobs": []})
                    else:
                        yield ev({"type": "response.content_part.added", **loc, "part": part})
                    yield ev({"type": "response.content_part.done", **loc, "part": part})
            elif item.get("type") == "function_call":
                yield ev({"type": "response.output_item.added", "output_index": oi,
                          "item": {**item, "arguments": "", "status": "in_progress"}})
                loc = {"item_id": item_id, "output_index": oi}
                yield ev({"type": "response.function_call_arguments.delta", **loc, "delta": item.get("arguments", "")})
                yield ev({"type": "response.function_call_arguments.done", **loc,
                          "arguments": item.get("arguments", "")})
            else:
                yield ev({"type": "response.output_item.added", "output_index": oi, "item": item})
            yield ev({"type": "response.output_item.done", "output_index": oi, "item": item})
        yield ev({"type": "response.completed", "response": resp})


_ANTHROPIC_ERRORS = {400: "invalid_request_error", 401: "authentication_error", 403: "permission_error",
                     404: "not_found_error", 413: "request_too_large", 429: "rate_limit_error"}


class AnthropicMessages(ApiFormat):
    name = "messages"

    def validate(self, body):
        if not isinstance(body.get("messages"), list):
            return "'messages' bir liste olmalı."
        if "system" in body and not isinstance(body["system"], (str, list)):
            return "'system' bir metin ya da blok listesi olmalı."
        return None

    @staticmethod
    def _blocks(blocks: List[Any], role: str) -> List[Part]:
        parts: List[Part] = []
        for b in blocks:
            if not isinstance(b, dict):
                continue
            t = b.get("type")
            if t == "text" and isinstance(b.get("text"), str):
                parts.append(_key(b, "text", role))
            elif t == "tool_result":
                c = b.get("content")
                if isinstance(c, str):
                    parts.append(_key(b, "content", "tool"))
                elif isinstance(c, list):
                    parts.extend(AnthropicMessages._blocks(c, "tool"))
            elif t == "tool_use":
                parts.extend(_leaves(b.get("input") or {}, "assistant"))
            elif t == "document" and (b.get("source") or {}).get("type") == "text":
                parts.append(_key(b["source"], "data", role))
            # thinking / redacted_thinking: imzalı, dokunulmaz. image / base64 belge: metin değil.
        return parts

    def request_parts(self, body):
        parts: List[Part] = []
        system = body.get("system")
        if isinstance(system, str):
            parts.append(_key(body, "system", "system"))
        elif isinstance(system, list):
            parts.extend(self._blocks(system, "system"))
        for msg in body.get("messages", []):
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "user")
            if isinstance(msg.get("content"), str):
                parts.append(_key(msg, "content", role))
            elif isinstance(msg.get("content"), list):
                parts.extend(self._blocks(msg["content"], role))
        return parts

    def response_parts(self, resp):
        parts: List[Part] = []
        for b in resp.get("content", []):
            if b.get("type") == "text" and isinstance(b.get("text"), str):
                parts.append(_key(b, "text", "assistant"))
            elif b.get("type") == "tool_use":
                parts.extend(_leaves(b.get("input") or {}, "assistant"))
        return parts

    def upstream(self, destination, headers, path="/v1/messages"):
        base = ANTHROPIC_UPSTREAMS.get(destination)
        if not base:
            return None
        h = {"content-type": "application/json",
             "anthropic-version": headers.get("anthropic-version", ANTHROPIC_VERSION)}
        if headers.get("anthropic-beta"):
            h["anthropic-beta"] = headers["anthropic-beta"]
        if ANTHROPIC_KEYS.get(destination):
            h["x-api-key"] = ANTHROPIC_KEYS[destination]
        return f"{base.rstrip('/')}{path}", h

    def usage(self, resp):
        u = (resp or {}).get("usage") or {}
        inp = int(u.get("input_tokens") or 0)
        cw = int(u.get("cache_creation_input_tokens") or 0)
        cr = int(u.get("cache_read_input_tokens") or 0)
        # Önbellek yazımı 1,25x, okuması 0,1x fiyatlanır (Claude Code yoğun önbellek kullanır)
        return inp + cw + cr, int(u.get("output_tokens") or 0), inp + 1.25 * cw + 0.1 * cr, bool(u)

    def error(self, status, message, code, type_=""):
        etype = _ANTHROPIC_ERRORS.get(status, "api_error")
        return JSONResponse(status_code=status, content={
            "type": "error", "error": {"type": etype, "message": message}, "telveguard_code": code})

    async def buffered_sse(self, resp):
        usage = resp.get("usage") or {}
        start = {**resp, "content": [], "stop_reason": None, "stop_sequence": None,
                 "usage": {**usage, "output_tokens": 0}}
        yield _sse("message_start", {"type": "message_start", "message": start})
        for i, b in enumerate(resp.get("content", [])):
            t = b.get("type")
            if t == "text":
                yield _sse("content_block_start", {"type": "content_block_start", "index": i,
                                                   "content_block": {"type": "text", "text": ""}})
                yield _sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "text_delta", "text": b.get("text", "")}})
            elif t == "tool_use":
                yield _sse("content_block_start", {"type": "content_block_start", "index": i,
                                                   "content_block": {**b, "input": {}}})
                yield _sse("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {
                    "type": "input_json_delta", "partial_json": json.dumps(b.get("input") or {}, ensure_ascii=False)}})
            elif t == "thinking":
                yield _sse("content_block_start", {"type": "content_block_start", "index": i,
                                                   "content_block": {"type": "thinking", "thinking": "", "signature": ""}})
                yield _sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "thinking_delta", "thinking": b.get("thinking", "")}})
                yield _sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "signature_delta", "signature": b.get("signature", "")}})
            else:  # redacted_thinking, sunucu araç sonuçları vb.: blok başta tam gelir
                yield _sse("content_block_start", {"type": "content_block_start", "index": i, "content_block": b})
            yield _sse("content_block_stop", {"type": "content_block_stop", "index": i})
        yield _sse("message_delta", {"type": "message_delta",
                                     "delta": {"stop_reason": resp.get("stop_reason"),
                                               "stop_sequence": resp.get("stop_sequence")},
                                     "usage": {"output_tokens": usage.get("output_tokens", 0)}})
        yield _sse("message_stop", {"type": "message_stop"})


CHAT, RESPONSES, MESSAGES = OpenAIChat(), OpenAIResponses(), AnthropicMessages()
FORMATS = {f.name: f for f in (CHAT, RESPONSES, MESSAGES)}
