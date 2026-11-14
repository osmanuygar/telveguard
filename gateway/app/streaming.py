"""
Artımlı streaming (STREAM_MODE=incremental): cevap akarken çıktı koruması.

Tamponlu yol cevabın tamamını bekler, tarar, sızıntıyı gizler, maskeyi geri açar ve tek parça
döner: ilk token gecikmesi cevabın tamamının süresidir. Bu modül upstream'in SSE'sini olay olay
okur ve her metin bloğunu bir TUTMA PENCERESİYLE işler:

  * bloğun sonundaki şu kısım henüz gönderilmez: son boşluksuz kelime (e-posta, anahtar, token tek
    kelimedir), son HOLDBACK karakter (boşluklu IBAN / kart / telefon, bölünmüş TCKN, çok kelimeli
    sözlük terimi), yarım yer tutucu (`[TCKN_`), sınırı kesen bir bulgu (kapanmamış private key
    metnin sonuna kadar uzanır: kendiliğinden tutulur)
  * gönderilebilir önek taranır: girdide olmayan PII / sır (sızıntı) çıktı politikasına göre
    gizlenir, yer tutucular geri açılır
  * blok bitince kalan gönderilir

Doğruluk şartı: herhangi bir parçalamada sonuç tamponlu yolla AYNIDIR (tests/test_streaming.py).
Bunu mümkün kılan: engelleme kuralı yokken bir sızıntının gizlenip gizlenmeyeceği yalnızca kendi
türüne bağlıdır (cevaptaki diğer sızıntılara değil). Eşleşebilecek bir `block` çıktı kuralı varsa
cevap tamponlanır (gönderilmiş metin geri alınamaz).

Araç argümanları (OpenAI tool_calls / function_call, Anthropic tool_use) blok bitene kadar
tutulur ve tamponlu yolla aynı biçimde (JSON yaprakları) işlenip tek parça gönderilir: istemciler
araç girdisini zaten tamamlanınca kullanır, JSON kaçışları bölünmez. Anthropic `thinking` blokları
imzalıdır, dokunulmaz (tamponlu yolda da).
"""
import json
import os
import re
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Set, Tuple

from telveguard_core.pii.engine import KnownValues

from .formats import Part, _json_string, _leaves

HOLDBACK = int(os.getenv("STREAM_HOLDBACK_CHARS", "64"))
# Yeni metin bu kadar birikmeden tarama yapılmaz: her delta'da (~1 token) pencereyi yeniden taramak
# tamponlu yolun ~40 katı CPU harcıyordu. Sonuç değişmez (daha kaba bir parçalama gibi); ilk token
# en fazla bu kadar karakter geç gelir.
SCAN_EVERY = int(os.getenv("STREAM_SCAN_EVERY_CHARS", "32"))
CONTEXT = 64            # geriye bakış: "vergi no:", "TC" bağlamı ve regex lookbehind'ları
_PLACEHOLDER = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")
_REDACTED = "[GİZLENDİ:{}]"


def incremental_enabled() -> bool:
    return os.getenv("STREAM_MODE", "buffer").lower() == "incremental"


def has_block_output_rule(policy) -> bool:
    """Uygulanan (gözlemde olmayan) bir `block` çıktı kuralı varsa artımlı akış yapılmaz."""
    return any(r.get("action") == "block" and r.get("mode", policy.mode) != "monitor"
               for r in policy.output_rules)


class OutputGuard:
    """Bir cevabın çıktı koruması: sızıntı tespiti, gizleme kararı, maskeyi geri açma, denetim için
    görülen / sızan türler. Tamponlu yoldaki `_find_output_leaks` + `_redact` + `unmask` ile aynı."""

    def __init__(self, pii, policy, ctx, known: str, vault: Dict[str, str], extra_holdback: int = 0):
        self.pii, self.policy, self.ctx = pii, policy, ctx
        self.known, self.vault = known, vault
        self.known_values = KnownValues(vault)
        self.holdback = max(HOLDBACK, extra_holdback)
        self.entities: Set[str] = set()
        self.leaked: Set[str] = set()
        self._mask_cache: Dict[str, bool] = {}

    def _masks(self, entity: str) -> bool:
        if entity not in self._mask_cache:
            d = self.policy.evaluate_output(self.ctx, {entity})
            self._mask_cache[entity] = d.action == "mask" and entity in d.mask_entities
        return self._mask_cache[entity]

    def _render(self, text: str, findings) -> str:
        """text içindeki bulgular (ofsetler text'e göre): kaydet, sızıntıyı gizle, maskeyi geri aç."""
        out, cursor = [], 0
        for f in findings:
            value = text[f.start:f.end]
            self.entities.add(f.entity)
            if value in self.known or value in self.known_values:
                continue
            self.leaked.add(f.entity)
            if self._masks(f.entity):
                out.append(text[cursor:f.start])
                out.append(_REDACTED.format(f.entity))
                cursor = f.end
        out.append(text[cursor:])
        return self.pii.unmask("".join(out), self.vault)

    def full(self, text: str) -> str:
        """Tam bir metin (araç argümanı yaprağı, tamponlanmış blok)."""
        return self._render(text, self.pii.analyze(text))

    def full_json_args(self, container: Dict[str, Any], key: str) -> None:
        """OpenAI tool_calls / function_call `arguments` (JSON metni): tamponlu yoldaki gibi yapraklar."""
        for p in _json_string(container, key, "assistant"):
            p.set(self.full(p.text))

    def full_leaves(self, obj: Any) -> None:
        """Anthropic tool_use `input` (nesne): yapraklar."""
        for p in _leaves(obj, "assistant"):
            p.set(self.full(p.text))


class TextBlock:
    """Tek bir metin bloğunun artımlı işlenmesi."""

    def __init__(self, guard: OutputGuard):
        self.g = guard
        self.text = ""          # upstream'den gelen ham metin
        self.pos = 0            # bu konuma kadar gönderildi
        self.out = ""           # istemciye giden (işlenmiş) metnin tamamı
        self._scanned = 0       # son taramada metnin uzunluğu

    def _findings(self) -> Tuple[int, list]:
        start = max(0, self.pos - CONTEXT)
        found = self.g.pii.analyze(self.text[start:])
        for f in found:
            f.start += start
            f.end += start
        return start, found

    def _safe_end(self, findings) -> int:
        t = self.text
        end = len(t) - self.g.holdback
        ws = max(t.rfind(" "), t.rfind("\n"), t.rfind("\t"), t.rfind("\r"))
        end = min(end, ws + 1)                     # son kelime (boşluksuz) tutulur
        bracket = t.rfind("[", max(self.pos, end - 64), end)
        if bracket >= 0 and "]" not in t[bracket:end]:
            end = bracket                          # yarım yer tutucu
        moved = True
        while moved and end > self.pos:
            moved = False
            for f in findings:                     # sınırı kesen bulgu (kapanmamış private key dahil)
                if f.start < end < f.end:
                    end, moved = f.start, True
            for m in _PLACEHOLDER.finditer(t, max(0, end - 64), min(len(t), end + 64)):
                if m.start() < end < m.end():
                    end, moved = m.start(), True
        return max(end, self.pos)

    def _emit(self, end: int, findings) -> str:
        seg = self.text[self.pos:end]
        local = [f for f in findings if f.start >= self.pos and f.end <= end]
        for f in local:
            f.start -= self.pos
            f.end -= self.pos
        out = self.g._render(seg, local)
        self.pos = end
        self.out += out
        return out

    def feed(self, delta: str) -> str:
        self.text += delta
        if len(self.text) - self._scanned < SCAN_EVERY:
            return ""
        self._scanned = len(self.text)
        _, findings = self._findings()
        return self._emit(self._safe_end(findings), findings)

    def finish(self) -> str:
        _, findings = self._findings()
        return self._emit(len(self.text), findings)


# ---------------- SSE ----------------

async def sse_events(chunks: AsyncIterator[bytes]) -> AsyncIterator[Tuple[Optional[str], str]]:
    """Upstream SSE -> (event adı, data metni). Yorum satırları ve boş olaylar atlanır."""
    buf = b""
    async for chunk in chunks:
        buf += chunk.replace(b"\r\n", b"\n")
        while b"\n\n" in buf:
            raw, buf = buf.split(b"\n\n", 1)
            event, data = None, []
            for line in raw.decode("utf-8").split("\n"):
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].lstrip(" "))
            if data:
                yield event, "\n".join(data)
    if buf.strip():
        event, data = None, []
        for line in buf.decode("utf-8").split("\n"):
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" "))
        if data:
            yield event, "\n".join(data)


def _sse(event: Optional[str], data: Any) -> bytes:
    head = f"event: {event}\n" if event else ""
    body = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    return f"{head}data: {body}\n\n".encode()


class Stream:
    """Format dönüştürücülerinin ortak durumu: usage (Röntgen / kota) ve ilk içerik zamanı."""

    def __init__(self, guard: OutputGuard, on_first: Callable[[], None] = lambda: None):
        self.g = guard
        self.usage: Optional[Dict[str, Any]] = None   # fmt.usage()'ın okuyacağı cevap biçiminde
        self._first = on_first

    def first(self, text: str) -> None:
        if text and self._first is not None:
            self._first()
            self._first = None


def _empty_choice(choice: Dict[str, Any]) -> bool:
    """Tutma penceresi yüzünden içeriği boş kalan parça: rol, araç çağrısı, bitiş yok."""
    delta = choice.get("delta") or {}
    return (not choice.get("finish_reason") and not choice.get("logprobs")
            and set(delta) <= {"content"} and not delta.get("content"))


async def openai_chat(stream: Stream, events, strip_usage: bool) -> AsyncIterator[bytes]:
    texts: Dict[int, TextBlock] = {}
    tools: Dict[int, Dict[int, Dict[str, Any]]] = {}
    async for event, data in events:
        if data.strip() == "[DONE]":
            yield _sse(None, "[DONE]")
            continue
        chunk = json.loads(data)
        if chunk.get("usage"):
            stream.usage = {"usage": chunk["usage"]}
            if strip_usage and not chunk.get("choices"):
                continue          # istemci istemedi; gateway Röntgen / kota için istedi
            if strip_usage:
                chunk.pop("usage", None)
        for choice in chunk.get("choices") or []:
            i = choice.get("index", 0)
            delta = choice.get("delta") or {}
            if isinstance(delta.get("content"), str):
                block = texts.setdefault(i, TextBlock(stream.g))
                delta["content"] = block.feed(delta["content"])
                stream.first(delta["content"])
            for tc in delta.pop("tool_calls", None) or []:
                slot = tools.setdefault(i, {}).setdefault(tc.get("index", 0), {"function": {"arguments": ""}})
                for k in ("id", "type"):
                    if tc.get(k):
                        slot[k] = tc[k]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["function"]["name"] = fn["name"]
                slot["function"]["arguments"] += fn.get("arguments") or ""
            if choice.get("finish_reason"):
                if i in texts:
                    rest = texts.pop(i).finish()
                    delta["content"] = (delta.get("content") or "") + rest
                if i in tools:
                    calls = []
                    for ti, call in sorted(tools.pop(i).items()):
                        stream.g.full_json_args(call["function"], "arguments")
                        calls.append({"index": ti, **call})
                    delta["tool_calls"] = calls
                stream.first("x")
            choice["delta"] = delta
        if chunk.get("choices") and all(_empty_choice(c) for c in chunk["choices"]) and not chunk.get("usage"):
            continue
        yield _sse(None, chunk)


async def anthropic_messages(stream: Stream, events) -> AsyncIterator[bytes]:
    texts: Dict[int, TextBlock] = {}
    tools: Dict[int, str] = {}
    usage: Dict[str, Any] = {}
    async for event, data in events:
        msg = json.loads(data)
        t = msg.get("type")
        if t == "message_start":
            usage.update((msg.get("message") or {}).get("usage") or {})
            stream.usage = {"usage": dict(usage)}
        elif t == "content_block_start":
            block = msg.get("content_block") or {}
            if block.get("type") == "text":
                texts[msg["index"]] = TextBlock(stream.g)
                if block.get("text"):     # başlangıçta metin gelirse (pratikte boş) delta gibi işle
                    block["text"] = texts[msg["index"]].feed(block["text"])
            elif block.get("type") == "tool_use":
                tools[msg["index"]] = ""
        elif t == "content_block_delta":
            i, delta = msg.get("index"), msg.get("delta") or {}
            if delta.get("type") == "text_delta" and i in texts:
                delta["text"] = texts[i].feed(delta.get("text", ""))
                stream.first(delta["text"])
                if not delta["text"]:
                    continue
            elif delta.get("type") == "input_json_delta" and i in tools:
                tools[i] += delta.get("partial_json", "")
                continue
        elif t == "content_block_stop":
            i = msg.get("index")
            if i in texts:
                rest = texts.pop(i).finish()
                if rest:
                    yield _sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                                       "delta": {"type": "text_delta", "text": rest}})
                    stream.first(rest)
            elif i in tools:
                raw = tools.pop(i)
                try:
                    obj = json.loads(raw) if raw.strip() else {}
                    holder = {"input": obj}
                    stream.g.full_leaves(holder["input"])
                    partial = json.dumps(holder["input"], ensure_ascii=False)
                except json.JSONDecodeError:
                    partial = stream.g.full(raw)
                yield _sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "input_json_delta", "partial_json": partial}})
                stream.first("x")
        elif t == "message_delta":
            usage.update(msg.get("usage") or {})
            stream.usage = {"usage": dict(usage)}
        yield _sse(event or t, msg)


async def openai_responses(stream: Stream, events) -> AsyncIterator[bytes]:
    texts: Dict[Tuple[int, int], TextBlock] = {}
    done_text: Dict[Tuple[int, int], str] = {}
    args: Dict[int, str] = {}
    done_args: Dict[int, str] = {}
    seq = 0

    def ev(data: Dict[str, Any]) -> bytes:
        nonlocal seq
        if "sequence_number" in data:      # olay ekleyip çıkardığımız için yeniden numaralanır
            data["sequence_number"] = seq
            seq += 1
        return _sse(data.get("type"), data)

    def patch_item(oi: int, item: Dict[str, Any]) -> None:
        if item.get("type") == "message":
            for ci, part in enumerate(item.get("content") or []):
                if part.get("type") == "output_text" and (oi, ci) in done_text:
                    part["text"] = done_text[(oi, ci)]
        elif item.get("type") == "function_call" and oi in done_args:
            item["arguments"] = done_args[oi]

    async for event, data in events:
        msg = json.loads(data)
        t = msg.get("type", event)
        oi, ci = msg.get("output_index"), msg.get("content_index")
        if t == "response.output_text.delta":
            block = texts.setdefault((oi, ci), TextBlock(stream.g))
            msg["delta"] = block.feed(msg.get("delta", ""))
            stream.first(msg["delta"])
            if not msg["delta"]:
                continue
        elif t == "response.output_text.done":
            block = texts.pop((oi, ci), None) or TextBlock(stream.g)
            if not block.text and msg.get("text"):       # delta'sız gelen metin
                block.text = msg["text"]
            rest = block.finish()
            if rest:
                yield ev({"type": "response.output_text.delta", "item_id": msg.get("item_id"),
                          "output_index": oi, "content_index": ci, "delta": rest, "logprobs": [],
                          "sequence_number": 0})
                stream.first(rest)
            done_text[(oi, ci)] = block.out
            msg["text"] = block.out
        elif t == "response.content_part.done":
            part = msg.get("part") or {}
            if part.get("type") == "output_text" and (oi, ci) in done_text:
                part["text"] = done_text[(oi, ci)]
        elif t == "response.function_call_arguments.delta":
            args[oi] = args.get(oi, "") + msg.get("delta", "")
            continue
        elif t == "response.function_call_arguments.done":
            holder = {"arguments": msg.get("arguments", args.pop(oi, ""))}
            args.pop(oi, None)
            stream.g.full_json_args(holder, "arguments")
            done_args[oi] = holder["arguments"]
            yield ev({"type": "response.function_call_arguments.delta", "item_id": msg.get("item_id"),
                      "output_index": oi, "delta": holder["arguments"], "sequence_number": 0})
            stream.first("x")
            msg["arguments"] = holder["arguments"]
        elif t == "response.output_item.done":
            patch_item(oi, msg.get("item") or {})
        elif t in ("response.completed", "response.incomplete", "response.failed"):
            resp = msg.get("response") or {}
            for i, item in enumerate(resp.get("output") or []):
                patch_item(i, item)
            if resp.get("usage"):
                stream.usage = {"usage": resp["usage"]}
        yield ev(msg)
