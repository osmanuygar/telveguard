"""
Artımlı streaming (STREAM_MODE=incremental): her parçalamada sonuç tamponlu yolla AYNI olmalı.

Upstream cevabı rastgele noktalardan bölünmüş delta'larla ve rastgele byte parçalarıyla (UTF-8
karakterinin ortası dahil) gönderir. Cevapta: geri açılacak yer tutucu, girdide olmayan kart /
bölünmüş TCKN / AWS anahtarı / private key (gizlenir), gözlemdeki e-posta (gizlenmez), bilinmeyen
yer tutucu (olduğu gibi), araç argümanında sır ve yer tutucu.
"""
import json
import random

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from app import formats, main
from telveguard_core.policy import PolicyEngine
from tests.test_tr_pii import make_tckn

AWS_KEY = "AKIA" + "Q3EXAMPLE7ABCDEF"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7x\nQWERTY\n-----END RSA PRIVATE KEY-----"
TCKN = make_tckn(1)
LEAK = make_tckn(7)
LEAK_SPLIT = f"{LEAK[:3]} {LEAK[3:6]} {LEAK[6:9]} {LEAK[9:]}"
USER = f"Müşteri TC {TCKN} için özet yaz"
state = {"seed": 0, "body": None}


def reply_text(masked_user: str) -> str:
    ph = masked_user.split("TC ", 1)[1].split(" ", 1)[0]          # [TCKN_1]
    return (f"Özet: {ph} numaralı müşteri, Çağrı İşleri şubesi. Sızan kart 4111 1111 1111 1111 ve "
            f"TC {LEAK_SPLIT}, anahtar {AWS_KEY}, e-posta yeni.adres@ornek.com.tr, özel anahtar:\n"
            f"{PRIVATE_KEY}\nTekrar{ph}, bilinmeyen [TCKN_99] ve son kelime {ph}")


def tool_args(masked_user: str) -> dict:
    ph = masked_user.split("TC ", 1)[1].split(" ", 1)[0]
    return {"path": "config.py", "content": f"KEY = '{AWS_KEY}'\n# müşteri {ph}\n"}


def _user_text(body) -> str:
    if "messages" in body:
        c = body["messages"][-1]["content"]
        return c if isinstance(c, str) else c[0]["text"]
    return body["input"] if isinstance(body["input"], str) else body["input"][-1]["content"]


def _cuts(text: str, rnd: random.Random):
    """Metni 1-7 karakterlik rastgele parçalara böler."""
    out, i = [], 0
    while i < len(text):
        n = rnd.randint(1, 7)
        out.append(text[i:i + n])
        i += n
    return out or [""]


def _sse(event, data) -> bytes:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)}\n\n".encode()


def chat_stream(body, text, args, rnd):
    base = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": body["model"]}
    yield _sse(None, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]})
    for piece in _cuts(text, rnd):
        yield _sse(None, {**base, "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}]})
    raw = json.dumps(args, ensure_ascii=False)
    for k, piece in enumerate(_cuts(raw, rnd)):
        tc = {"index": 0, "function": {"arguments": piece}}
        if k == 0:
            tc.update(id="call_1", type="function", function={"name": "write_file", "arguments": piece})
        yield _sse(None, {**base, "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": None}]})
    yield _sse(None, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
    if (body.get("stream_options") or {}).get("include_usage"):
        yield _sse(None, {**base, "choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 50,
                                                          "total_tokens": 150}})
    yield _sse(None, "[DONE]")


def chat_reply(body, text, args):
    return {"id": "c1", "object": "chat.completion", "created": 0, "model": body["model"],
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": text,
                "tool_calls": [{"id": "call_1", "type": "function", "function": {
                    "name": "write_file", "arguments": json.dumps(args, ensure_ascii=False)}}]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}


def anthropic_stream(body, text, args, rnd):
    msg = {"id": "m1", "type": "message", "role": "assistant", "model": body["model"], "content": [],
           "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 100, "output_tokens": 1}}
    yield _sse("message_start", {"type": "message_start", "message": msg})
    yield _sse("ping", {"type": "ping"})
    yield _sse("content_block_start", {"type": "content_block_start", "index": 0,
                                       "content_block": {"type": "text", "text": ""}})
    for piece in _cuts(text, rnd):
        yield _sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                           "delta": {"type": "text_delta", "text": piece}})
    yield _sse("content_block_stop", {"type": "content_block_stop", "index": 0})
    yield _sse("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {
        "type": "tool_use", "id": "tu_1", "name": "write_file", "input": {}}})
    for piece in _cuts(json.dumps(args, ensure_ascii=False), rnd):
        yield _sse("content_block_delta", {"type": "content_block_delta", "index": 1,
                                           "delta": {"type": "input_json_delta", "partial_json": piece}})
    yield _sse("content_block_stop", {"type": "content_block_stop", "index": 1})
    yield _sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                                 "usage": {"output_tokens": 50}})
    yield _sse("message_stop", {"type": "message_stop"})


def anthropic_reply(body, text, args):
    return {"id": "m1", "type": "message", "role": "assistant", "model": body["model"],
            "content": [{"type": "text", "text": text},
                        {"type": "tool_use", "id": "tu_1", "name": "write_file", "input": args}],
            "stop_reason": "tool_use", "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 50}}


def responses_reply(body, text, args):
    return {"id": "r1", "object": "response", "created_at": 0, "model": body["model"], "status": "completed",
            "output": [
                {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed",
                 "content": [{"type": "output_text", "text": text, "annotations": []}]},
                {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "write_file",
                 "arguments": json.dumps(args, ensure_ascii=False), "status": "completed"}],
            "usage": {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150}}


def responses_stream(body, text, args, rnd):
    resp = responses_reply(body, text, args)
    seq = iter(range(10_000))

    def ev(d):
        return _sse(d["type"], {**d, "sequence_number": next(seq)})
    yield ev({"type": "response.created", "response": {**resp, "status": "in_progress", "output": []}})
    msg, fc = resp["output"]
    yield ev({"type": "response.output_item.added", "output_index": 0, "item": {**msg, "content": []}})
    loc = {"item_id": "msg_1", "output_index": 0, "content_index": 0}
    yield ev({"type": "response.content_part.added", **loc, "part": {"type": "output_text", "text": ""}})
    for piece in _cuts(text, rnd):
        yield ev({"type": "response.output_text.delta", **loc, "delta": piece, "logprobs": []})
    yield ev({"type": "response.output_text.done", **loc, "text": text, "logprobs": []})
    yield ev({"type": "response.content_part.done", **loc, "part": msg["content"][0]})
    yield ev({"type": "response.output_item.done", "output_index": 0, "item": msg})
    yield ev({"type": "response.output_item.added", "output_index": 1, "item": {**fc, "arguments": ""}})
    for piece in _cuts(fc["arguments"], rnd):
        yield ev({"type": "response.function_call_arguments.delta", "item_id": "fc_1", "output_index": 1,
                  "delta": piece})
    yield ev({"type": "response.function_call_arguments.done", "item_id": "fc_1", "output_index": 1,
              "arguments": fc["arguments"]})
    yield ev({"type": "response.output_item.done", "output_index": 1, "item": fc})
    yield ev({"type": "response.completed", "response": resp})


FORMATS = {
    "/chat/completions": (chat_reply, chat_stream),
    "/v1/messages": (anthropic_reply, anthropic_stream),
    "/responses": (responses_reply, responses_stream),
}


def upstream(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    state["body"] = body
    reply, stream = next(v for k, v in FORMATS.items() if request.url.path.endswith(k))
    masked = _user_text(body)
    text, args = reply_text(masked), tool_args(masked)
    if not body.get("stream"):
        return httpx.Response(200, json=reply(body, text, args))
    rnd = random.Random(state["seed"])
    raw = b"".join(stream(body, text, args, rnd))

    async def chunks():   # rastgele byte parçaları: olay ve UTF-8 karakter sınırı ortasından
        i = 0
        while i < len(raw):
            n = rnd.randint(1, 40)
            yield raw[i:i + n]
            i += n
    return httpx.Response(200, content=chunks(), headers={"content-type": "text/event-stream"})


@pytest.fixture()
def c(monkeypatch):
    monkeypatch.setenv("STREAM_MODE", "incremental")
    monkeypatch.setitem(formats.ANTHROPIC_KEYS, "external", "k")
    main.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    with TestClient(main.app) as client:
        client.events = []

        async def capture(ev):
            client.events.append(ev)
        client.app.state.audit.emit = capture
        yield client


def _events(r):
    out = []
    for raw in r.text.split("\n\n"):
        data = [ln[6:] for ln in raw.split("\n") if ln.startswith("data: ")]
        if data and data[0] != "[DONE]":
            out.append(json.loads(data[0]))
    return out


def chat(c, stream):
    return c.post("/v1/chat/completions", json={"model": "gpt-4o", "stream": stream,
                                                "messages": [{"role": "user", "content": USER}]})


def messages(c, stream):
    return c.post("/v1/messages", json={"model": "claude-opus-5", "max_tokens": 100, "stream": stream,
                                        "messages": [{"role": "user", "content": USER}]})


def responses(c, stream):
    return c.post("/v1/responses", json={"model": "gpt-4o", "stream": stream, "input": USER})


def buffered(c, call):
    r = call(c, False)
    assert r.status_code == 200, r.text
    return r.json()


def test_reference_buffered_result_is_what_we_expect(c):
    """Karşılaştırma tabanı doğru mu: tamponlu yol gizler / geri açar."""
    msg = buffered(c, chat)["choices"][0]["message"]
    text = msg["content"]
    assert TCKN in text and "[TCKN_99]" in text and "yeni.adres@ornek.com.tr" in text   # gözlem: gizlenmez
    for leak in ("4111 1111 1111 1111", LEAK_SPLIT, AWS_KEY, "MIIEowIBAAKCAQEA7x"):
        assert leak not in text
    assert "[GİZLENDİ:CREDIT_CARD]" in text and "[GİZLENDİ:SECRET_PRIVATE_KEY]" in text
    args = json.loads(msg["tool_calls"][0]["function"]["arguments"])
    assert AWS_KEY not in args["content"] and TCKN in args["content"]


@pytest.mark.parametrize("seed", range(25))
def test_chat_incremental_equals_buffered(c, seed):
    want = buffered(c, chat)["choices"][0]["message"]
    state["seed"] = seed
    r = chat(c, True)
    assert r.status_code == 200 and state["body"]["stream"] is True        # gerçekten aktı
    evs = _events(r)
    text = "".join(e["choices"][0]["delta"].get("content") or "" for e in evs if e.get("choices"))
    assert text == want["content"]
    calls = [tc for e in evs if e.get("choices") for tc in e["choices"][0]["delta"].get("tool_calls") or []]
    assert len(calls) == 1 and calls[0]["function"] == want["tool_calls"][0]["function"]
    assert all("usage" not in e or e["usage"] is None for e in evs)          # istemci istemedi
    ev = c.events[-1]
    assert ev["prompt_tokens"] == 100 and ev["completion_tokens"] == 50 and ev["usage_known"] == 1
    assert {"CREDIT_CARD", "TCKN", "SECRET_AWS_KEY", "SECRET_PRIVATE_KEY", "EMAIL_ADDRESS"} <= set(ev["output_leaked"])
    assert ev["output_action"] == "mask" and ev["stream_aborted"] == 0


@pytest.mark.parametrize("seed", range(25))
def test_messages_incremental_equals_buffered(c, seed):
    want = buffered(c, messages)["content"]
    state["seed"] = seed
    r = messages(c, True)
    assert r.status_code == 200 and state["body"]["stream"] is True
    evs = _events(r)
    text = "".join(e["delta"]["text"] for e in evs
                   if e["type"] == "content_block_delta" and e["delta"]["type"] == "text_delta")
    assert text == want[0]["text"]
    raw = "".join(e["delta"]["partial_json"] for e in evs
                  if e["type"] == "content_block_delta" and e["delta"]["type"] == "input_json_delta")
    assert json.loads(raw) == want[1]["input"]
    assert c.events[-1]["prompt_tokens"] == 100 and c.events[-1]["completion_tokens"] == 50


@pytest.mark.parametrize("seed", range(25))
def test_responses_incremental_equals_buffered(c, seed):
    want = buffered(c, responses)["output"]
    state["seed"] = seed
    r = responses(c, True)
    assert r.status_code == 200 and state["body"]["stream"] is True
    evs = _events(r)
    text = "".join(e["delta"] for e in evs if e["type"] == "response.output_text.delta")
    assert text == want[0]["content"][0]["text"]
    done = next(e for e in evs if e["type"] == "response.output_text.done")
    assert done["text"] == text
    completed = next(e for e in evs if e["type"] == "response.completed")["response"]
    assert completed["output"][0]["content"][0]["text"] == text
    assert completed["output"][1]["arguments"] == want[1]["arguments"]
    args = "".join(e["delta"] for e in evs if e["type"] == "response.function_call_arguments.delta")
    assert args == want[1]["arguments"]
    assert [e["sequence_number"] for e in evs] == list(range(len(evs)))
    assert c.events[-1]["prompt_tokens"] == 100


def test_sdks_parse_incremental_streams(c):
    anthropic = pytest.importorskip("anthropic")
    openai = pytest.importorskip("openai")
    state["seed"] = 3
    cl = anthropic.Anthropic(base_url="http://testserver", api_key="x", http_client=c, max_retries=0)
    with cl.messages.stream(model="claude-opus-5", max_tokens=100,
                            messages=[{"role": "user", "content": USER}]) as s:
        final = s.get_final_message()
    assert TCKN in final.content[0].text and AWS_KEY not in final.content[0].text
    assert final.content[1].input["content"].startswith("KEY = '[GİZLENDİ:SECRET_AWS_KEY]'")
    oc = openai.OpenAI(base_url="http://testserver/v1", api_key="x", http_client=c, max_retries=0)
    text = "".join(ch.choices[0].delta.content or "" for ch in oc.chat.completions.create(
        model="gpt-4o", stream=True, messages=[{"role": "user", "content": USER}]) if ch.choices)
    assert TCKN in text and LEAK_SPLIT not in text
    with oc.responses.stream(model="gpt-4o", input=USER) as s:
        resp = s.get_final_response()
    assert TCKN in resp.output_text and "[GİZLENDİ:CREDIT_CARD]" in resp.output_text


def test_client_requested_usage_is_kept(c):
    r = c.post("/v1/chat/completions", json={"model": "gpt-4o", "stream": True,
                                             "stream_options": {"include_usage": True},
                                             "messages": [{"role": "user", "content": USER}]})
    assert any(e.get("usage", {}) and e["usage"]["total_tokens"] == 150 for e in _events(r))


def test_block_output_rule_falls_back_to_buffering(c, tmp_path):
    cfg = yaml.safe_load(open("policies/default.yaml", encoding="utf-8"))
    cfg["output_rules"].append({"name": "kart-engelle", "when": {"entity_in": ["CREDIT_CARD"]}, "action": "block"})
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    c.app.state.policy = PolicyEngine(str(p))
    r = chat(c, True)
    assert state["body"]["stream"] is False and r.status_code == 403      # tamponlandı ve engellendi


def test_upstream_error_on_stream(c, monkeypatch):
    def failing(request):
        return httpx.Response(429, json={"error": {"message": "yavaş", "type": "rate_limit"}})
    c.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(failing))
    r = chat(c, True)
    assert r.status_code == 429 and r.json()["error"]["message"] == "yavaş"
    assert c.events[-1]["upstream_status"] == 429


def test_buffer_mode_is_still_default(c, monkeypatch):
    monkeypatch.delenv("STREAM_MODE")
    chat(c, True)
    assert state["body"]["stream"] is False
