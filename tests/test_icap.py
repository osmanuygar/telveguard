"""Ağ tarafı (ICAP REQMOD): kurum proxy'si masaüstü uygulamalarının AI isteklerini sorar."""
import base64
import gzip
import json
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from app import icap, main
from tests.test_tr_pii import make_tckn


@pytest.fixture()
def gw(monkeypatch):
    monkeypatch.setenv("ICAP_PORT", "0")
    monkeypatch.setenv("ICAP_TEAM_PREFIX", "telveguard-")
    main.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with TestClient(main.app) as c:
        events = []

        async def capture(ev):
            events.append(ev)
        c.app.state.audit.emit = capture
        yield c.app.state.icap.port, events


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def http_request(host: str, path: str, body: bytes, ctype="application/json", extra="") -> bytes:
    return (f"POST https://{host}{path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n{extra}\r\n").encode()


def reqmod(port: int, http_head: bytes, body: bytes = b"", headers: str = "Allow: 204\r\n",
           preview: bool = False) -> bytes:
    enc = f"req-hdr=0, req-body={len(http_head)}" if body else f"req-hdr=0, null-body={len(http_head)}"
    msg = (f"REQMOD icap://127.0.0.1:{port}/reqmod ICAP/1.0\r\nHost: 127.0.0.1\r\n"
           f"Encapsulated: {enc}\r\n{headers}" + ("Preview: 0\r\n" if preview else "") +
           "Connection: close\r\n\r\n").encode() + http_head
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        if body and preview:
            s.sendall(msg + b"0\r\n\r\n")             # önizleme boş, ieof yok
            assert s.recv(100).startswith(b"ICAP/1.0 100 Continue")
            s.sendall(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        else:
            s.sendall(msg + ((f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n") if body else b""))
        return _read_all(s)


def _read_all(s: socket.socket) -> bytes:
    out = b""
    while chunk := s.recv(65536):
        out += chunk
    return out


def http_body(r: bytes) -> bytes:
    """ICAP cevabındaki kapsüllenmiş HTTP gövdesi (tek parça)."""
    chunked = r[r.index(b"HTTP/1.1"):].split(b"\r\n\r\n", 1)[1]
    size, rest = chunked.split(b"\r\n", 1)
    return rest[:int(size, 16)]


def chatgpt(text: str) -> bytes:
    return json.dumps({"action": "next", "messages": [{"id": "a1b2", "author": {"role": "user"},
                       "content": {"content_type": "text", "parts": [text]}}], "model": "auto"}).encode()


USER = "X-Authenticated-User: " + b64("SIRKET\\Ayse.Yilmaz") + "\r\n"


def test_options(gw):
    port, _ = gw
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"OPTIONS icap://127.0.0.1/reqmod ICAP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n")
        r = _read_all(s).decode()
    assert r.startswith("ICAP/1.0 200 OK") and "Methods: REQMOD" in r and "Allow: 204" in r


def test_chatgpt_prompt_with_tckn_blocked_and_recorded(gw):
    port, events = gw
    tckn = make_tckn()
    body = chatgpt(f"{tckn} numaralı müşterinin şikayetini özetle")
    r = reqmod(port, http_request("chatgpt.com", "/backend-api/f/conversation", body), body, "Allow: 204\r\n" + USER)
    assert r.startswith(b"ICAP/1.0 200 OK") and b"HTTP/1.1 403 Forbidden" in r
    msg = json.loads(http_body(r))
    assert "TCKN" in msg["error"]["message"] and tckn not in msg["error"]["message"]
    ev, = events
    assert (ev["api_format"], ev["model"], ev["user"], ev["action"]) == ("icap", "chatgpt.com", "ayse.yilmaz", "block")
    assert ev["entities"] == ["TCKN"] and "golge-ai:blocked" in ev["rules"] and ev["auth_source"] == "icap"
    assert tckn not in json.dumps(ev, ensure_ascii=False)


def test_clean_prompt_passes_and_is_recorded_for_usage(gw):
    port, events = gw
    body = chatgpt("Bu e-postayı daha kibar yaz")
    r = reqmod(port, http_request("chatgpt.com", "/backend-api/conversation", body), body, "Allow: 204\r\n" + USER)
    assert r.startswith(b"ICAP/1.0 204")
    assert [(e["action"], e["model"]) for e in events] == [("allow", "chatgpt.com")]


def test_other_requests_recorded_only_when_something_found(gw):
    port, events = gw
    body = b'{"event":"page_view","ts":1}'
    assert reqmod(port, http_request("chatgpt.com", "/ces/v1/t", body), body).startswith(b"ICAP/1.0 204")
    assert events == []


def test_unknown_host_untouched(gw):
    port, events = gw
    body = chatgpt(f"TC {make_tckn()}")
    assert reqmod(port, http_request("intranet.sirket.local", "/api", body), body).startswith(b"ICAP/1.0 204")
    assert events == []


def test_api_secret_blocked_with_json_error_for_sdks(gw):
    port, events = gw
    body = json.dumps({"model": "gpt-4o", "messages": [
        {"role": "user", "content": "bu config neden çalışmıyor: aws_key=AKIAIOSFODNN7EXAMPLE"}]}).encode()
    r = reqmod(port, http_request("api.openai.com", "/v1/chat/completions", body), body)
    assert b"403 Forbidden" in r and b"application/json" in r
    assert events[0]["model"] == "api.openai.com" and any(e.startswith("SECRET_") for e in events[0]["entities"])


def test_browser_gets_html_page(gw):
    port, _ = gw
    body = chatgpt(f"TC {make_tckn()}")
    r = reqmod(port, http_request("chatgpt.com", "/backend-api/conversation", body, extra="Accept: text/html\r\n"), body)
    assert b"text/html" in r and "Gönderilmedi".encode() in r


def test_without_204_original_request_echoed(gw):
    port, _ = gw
    body = chatgpt("merhaba")
    head = http_request("chatgpt.com", "/backend-api/conversation", body)
    r = reqmod(port, head, body, headers="")
    assert r.startswith(b"ICAP/1.0 200 OK") and head in r and body in r


def test_preview_continue(gw):
    port, events = gw
    body = chatgpt(f"TC {make_tckn()}")
    r = reqmod(port, http_request("claude.ai", "/api/organizations/o1/chat_conversations/c1/completion", body),
               body, preview=True)
    assert b"403 Forbidden" in r and events[0]["model"] == "claude.ai"


def test_groups_become_teams(gw):
    port, events = gw
    body = chatgpt("toplantı notlarını özetle")
    groups = "X-Authenticated-Groups: " + b64("CN=telveguard-yazilim,OU=Gruplar,DC=sirket,DC=local") + "\r\n"
    reqmod(port, http_request("chatgpt.com", "/backend-api/conversation", body), body, "Allow: 204\r\n" + USER + groups)
    assert events[0]["team"] == "yazilim"


def test_get_requests_not_inspected(gw):
    port, events = gw
    head = b"GET https://chatgpt.com/ HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n"
    assert reqmod(port, head).startswith(b"ICAP/1.0 204") and events == []


# ---------------- birim ----------------

def test_untrusted_proxy_rejected():
    s = icap.Settings(allowed=[__import__("ipaddress").ip_network("10.0.0.0/24")])
    assert s.client_allowed("10.0.0.7") and s.client_allowed("::ffff:10.0.0.7")
    assert not s.client_allowed("10.0.1.7") and not s.client_allowed("bozuk")


@pytest.mark.parametrize("raw,user", [
    ("ayse", "ayse"), ("SIRKET\\Ayse", "ayse"), ("WinNT://SIRKET/ayse", "ayse"),
    ("LDAP://dc1/CN=ayse,OU=Kullanicilar,DC=sirket", "ayse"), ("ayse@sirket.com.tr", "ayse@sirket.com.tr"),
    ("<script>", None)])
def test_proxy_user_formats(raw, user):
    assert icap.proxy_user({"x-authenticated-user": b64(raw)}) == user


def test_extract_gemini_form_with_nested_json():
    tckn = make_tckn()
    inner = json.dumps([[f"müşteri {tckn}", 0, None], ["tr"]])
    body = ("f.req=" + __import__("urllib.parse").parse.quote(json.dumps([None, inner])) + "&at=xyz").encode()
    text, bad = icap.extract_text(body, "application/x-www-form-urlencoded;charset=UTF-8")
    assert tckn in text and not bad


def test_extract_multipart_text_file_and_binary():
    tckn = make_tckn()
    body = ("--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"m.csv\"\r\nContent-Type: text/csv\r\n\r\n"
            f"ad,tc\r\nAyşe,{tckn}\r\n--b\r\nContent-Disposition: form-data; name=\"img\"; filename=\"a.png\"\r\n"
            "Content-Type: image/png\r\n\r\n\x89PNG\r\n--b--\r\n").encode("utf-8")
    text, bad = icap.extract_text(body, "multipart/form-data; boundary=b")
    assert tckn in text and bad   # görsel okunamadı


def test_extract_gzip_and_unknown_encoding():
    raw = json.dumps({"q": "merhaba dünya"}).encode()
    assert icap.extract_text(gzip.compress(raw), "application/json", "gzip") == ("merhaba dünya", False)
    assert icap.extract_text(raw, "application/json", "br") == ("", True)


def test_unscannable_policy(gw, monkeypatch):
    port, events = gw
    monkeypatch.setenv("ICAP_UNSCANNABLE", "block")
    body = b"\x00\x01binary"
    r = reqmod(port, http_request("chatgpt.com", "/backend-api/files/upload", body, ctype="application/octet-stream"), body)
    assert b"403" in r and "ag:okunamadi" in events[0]["rules"]


# ---------------- sağlamlaştırma ----------------

def test_decompression_is_bounded():
    raw = json.dumps({"q": "a" * 200_000}).encode()
    out, over = icap.decode_body(gzip.compress(raw), "gzip", limit=10_000)
    assert len(out) <= 10_000 and over
    out, over = icap.decode_body(gzip.compress(b'{"q":"kisa"}'), "gzip", limit=10_000)
    assert out == b'{"q":"kisa"}' and not over
    with pytest.raises(ValueError):
        icap.decode_body(b"gzip degil", "gzip")


def test_parse_failure_does_not_drop_connection(gw, monkeypatch):
    """Ayrıştırma hatası bağlantıyı düşürmez (proxy'nin bypass'ı taramayı atlamasın): okunamadı sayılır."""
    port, events = gw
    monkeypatch.setenv("ICAP_UNSCANNABLE", "block")
    def boom(*a, **k):
        raise RecursionError("derin")
    monkeypatch.setattr(icap, "extract_text", boom)
    body = chatgpt("merhaba")
    r = reqmod(port, http_request("chatgpt.com", "/backend-api/conversation", body), body)
    assert r.startswith(b"ICAP/1.0 200") and b"403 Forbidden" in r and "ag:okunamadi" in events[0]["rules"]


def test_oversize_body_blocked_by_default(gw, monkeypatch):
    port, events = gw
    main.app.state.icap.settings.max_body = 1000
    body = chatgpt("x" * 2000 + f" TC {make_tckn()}")
    r = reqmod(port, http_request("chatgpt.com", "/backend-api/conversation", body), body)
    assert b"403 Forbidden" in r and "ag:boyut-siniri" in events[0]["rules"]
    monkeypatch.setenv("ICAP_OVERSIZE", "allow")
    assert reqmod(port, http_request("chatgpt.com", "/backend-api/conversation", body), body).startswith(b"ICAP/1.0 204")
