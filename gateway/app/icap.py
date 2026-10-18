"""
Ağ tarafı (ICAP, RFC 3507): masaüstü AI uygulamaları ve eklentisiz tarayıcılar için.

Tarayıcı eklentisi yalnızca tarayıcıyı, telve yalnızca kod asistanlarını görür. Claude Desktop,
ChatGPT masaüstü, Copilot uygulaması, Office eklentileri, Python betikleri ... kurumun proxy'sinden
(Squid, Symantec / Broadcom ProxySG, Forcepoint, Zscaler ...) çıkar. Proxy TLS denetimi yapıyorsa
çözülmüş isteği ICAP ile Telveguard'a sorar (REQMOD); karar burada merkezi politikayla verilir.

Neden maskeleme yok? chatgpt.com, claude.ai gibi siteler belgelenmemiş, sık değişen iç API'ler
kullanır; gövdeyi yeniden yazmak her güncellemede kırılır ve sohbeti bozar. Burada gövdedeki
tüm metin (biçimden bağımsız) taranır, karar yalnızca "geçir" ya da "durdur"dur. Politika
"maskele" diyorsa istek durdurulur (Cursor hook'undaki gibi: maskesiz gitmesin).

Kimlik: proxy'nin doğruladığı kullanıcı (X-Authenticated-User, base64) ve isteğe bağlı gruplar
(X-Authenticated-Groups). Bu başlıklara yalnızca ICAP_ALLOWED_CLIENTS'taki proxy'lerden gelen
bağlantılarda güvenilir; diğer bağlantılar reddedilir.

Bu modül protokol ve metin çıkarma işini yapar; karar ve denetim kaydı main.icap_check'te.
"""
import asyncio
import base64
import gzip
import ipaddress
import json
import logging
import os
import re
import zlib
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import HTTP
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

log = logging.getLogger("telveguard.icap")

# Bilinen AI siteleri: ad ve "prompt gönderimi" yolları. Yol eşleşen istek her zaman kayda
# geçer (kullanım görünürlüğü); sitenin diğer POST'ları (dosya yükleme, ayarlar ...) yalnızca
# bir şey bulunursa. Yollar sitelerin iç API'leridir, değişebilir: değişirse yalnızca kullanım
# sayımı etkilenir, tarama ve engelleme sitenin tüm POST'larında yapılır.
SITES: Dict[str, Tuple[str, List[str]]] = {
    "chatgpt.com": ("ChatGPT", [r"^/backend-(api|anon)/(f/)?conversation$"]),
    "chat.openai.com": ("ChatGPT", [r"^/backend-(api|anon)/(f/)?conversation$"]),
    "claude.ai": ("Claude", [r"^/api/organizations/[^/]+/chat_conversations/[^/]+/(retry_)?completion$"]),
    "gemini.google.com": ("Gemini", [r"StreamGenerate"]),
    "copilot.microsoft.com": ("Microsoft Copilot", []),
    "chat.deepseek.com": ("DeepSeek", [r"^/api/v0/chat/completion$"]),
    "chat.mistral.ai": ("Le Chat", []),
    "www.perplexity.ai": ("Perplexity", [r"^/rest/sse/perplexity_ask$"]),
    "grok.com": ("Grok", [r"/conversations/.*/responses$|/conversations/new$"]),
    # Resmi API'ler: kurum içi betikler, masaüstü araçları, kayıtsız entegrasyonlar
    "api.openai.com": ("OpenAI API", [r"^/v1/(chat/completions|responses|completions)$"]),
    "api.anthropic.com": ("Anthropic API", [r"^/v1/messages$"]),
    "generativelanguage.googleapis.com": ("Gemini API", [r":(stream)?[gG]enerateContent$"]),
    "api.mistral.ai": ("Mistral API", [r"^/v1/chat/completions$"]),
    "api.deepseek.com": ("DeepSeek API", [r"^/(v1/)?chat/completions$"]),
}
SCANNED_METHODS = {"POST", "PUT", "PATCH"}
TEXT_TYPES = ("json", "text/", "x-www-form-urlencoded", "xml", "javascript", "csv", "yaml")
MIN_STRING = 2          # tek karakterlik JSON değerleri (bayraklar, ayraçlar) taranmaz
MAX_HEADER = 64 * 1024  # ICAP + HTTP başlıkları
HARD_BODY_LIMIT = 64 * 1024 * 1024  # 204 kullanılamıyorsa gövde geri gönderilmek üzere tutulur


class IcapError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


@dataclass
class IcapRequest:
    method: str
    uri: str
    headers: Dict[str, str]                 # küçük harf anahtarlar
    http_head: bytes = b""                  # kapsüllenmiş HTTP istek satırı + başlıklar (ham)
    body: bytes = b""
    body_truncated: bool = False
    client_ip: str = ""

    @property
    def allow_204(self) -> bool:
        return "204" in self.headers.get("allow", "")

    def http(self) -> "HttpRequest":
        return HttpRequest.parse(self.http_head)


@dataclass
class HttpRequest:
    method: str
    url: str
    host: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: bytes) -> "HttpRequest":
        lines = raw.decode("latin-1").split("\r\n")
        try:
            method, url, _ = lines[0].split(" ", 2)
        except ValueError:
            raise IcapError(400, "Kapsüllenmiş HTTP istek satırı okunamadı")
        headers = _parse_headers(lines[1:])
        parts = urlsplit(url)
        host = (parts.hostname or headers.get("host", "").split(":")[0]).lower().rstrip(".")
        return cls(method.upper(), url, host, parts.path if parts.scheme else url.split("?")[0], headers)


@dataclass
class Site:
    host: str
    name: str
    prompt: bool    # bu istek bir prompt gönderimi mi (her zaman kayda geçer)


def _parse_headers(lines: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep:
            key = name.strip().lower()
            out[key] = f"{out[key]}, {value.strip()}" if key in out else value.strip()
    return out


def match_site(http: HttpRequest, extra_hosts: Iterable[str] = ()) -> Optional[Site]:
    """Alt alan adları da eşleşir (ör. eu.api.openai.com). Yalnızca gövde taşıyan istekler."""
    if http.method not in SCANNED_METHODS:
        return None
    for known, (name, paths) in list(SITES.items()) + [(h, (h, [])) for h in extra_hosts]:
        if http.host == known or http.host.endswith("." + known):
            return Site(http.host, name, any(re.search(p, http.path) for p in paths))
    return None


# ---------------- gövdeden metin ----------------

def _walk_json(value, out: List[str], depth: int = 0) -> None:
    if depth > 40:
        return
    if isinstance(value, str):
        s = value.strip()
        # Gemini gibi siteler JSON'u string içinde taşır (f.req=[[...]]): içini de aç
        if len(s) > 1 and s[0] in "[{" and s[-1] in "]}":
            try:
                return _walk_json(json.loads(s), out, depth + 1)
            except ValueError:
                pass
        if len(s) >= MIN_STRING:
            out.append(s)
    elif isinstance(value, dict):
        for v in value.values():
            _walk_json(v, out, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _walk_json(v, out, depth + 1)


def _decode(body: bytes, encoding: str) -> bytes:
    encoding = encoding.strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding in ("gzip", "x-gzip"):
        return gzip.decompress(body)
    if encoding == "deflate":
        return zlib.decompress(body)
    raise ValueError(f"desteklenmeyen sıkıştırma: {encoding}")


def _is_text(content_type: str) -> bool:
    return any(t in content_type for t in TEXT_TYPES)


def extract_text(body: bytes, content_type: str, content_encoding: str = "") -> Tuple[str, bool]:
    """Gövdedeki insan metni (biçimden bağımsız). İkinci değer: okunamayan içerik var mı
    (sıkıştırma, ikili dosya). Biçim bilinmiyorsa metin olarak denenir."""
    try:
        body = _decode(body, content_encoding)
    except (ValueError, OSError, zlib.error):
        return "", True
    ct = content_type.lower()
    if "multipart/" in ct:
        msg = BytesParser(policy=HTTP).parsebytes(b"content-type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body)
        texts, unscannable = [], False
        for part in msg.iter_parts():
            payload = part.get_payload(decode=True) or b""
            pct = part.get_content_type()
            if part.get_filename() and not _is_text(pct):
                unscannable = unscannable or bool(payload)
                continue
            text, bad = extract_text(payload, pct)
            texts.append(text)
            unscannable = unscannable or bad
        return "\n".join(t for t in texts if t), unscannable
    text = body.decode("utf-8", errors="replace")
    if "x-www-form-urlencoded" in ct:
        out: List[str] = []
        for _, v in parse_qsl(text, keep_blank_values=False):
            _walk_json(v, out)
        return "\n".join(out), False
    if "json" in ct or text.lstrip()[:1] in ("{", "["):
        try:
            out = []
            _walk_json(json.loads(text), out)
            return "\n".join(out), False
        except ValueError:
            # NDJSON / SSE benzeri gövde: satır satır
            out = []
            for line in text.splitlines():
                try:
                    _walk_json(json.loads(line.removeprefix("data:").strip()), out)
                except ValueError:
                    if line.strip():
                        out.append(line.strip())
            return "\n".join(out), False
    if ct and not _is_text(ct):
        return "", bool(body)
    return text, "�" in text and text.count("�") > len(text) // 10


# ---------------- kimlik ----------------

_USER = re.compile(r"^[\w.@+-]{1,200}$", re.UNICODE)


def _b64(value: str) -> str:
    try:
        return base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value.strip()   # bazı proxy'ler düz metin gönderir


def proxy_user(headers: Dict[str, str]) -> Optional[str]:
    """X-Authenticated-User: Squid "user" / "DOMAIN\\user", ProxySG "WinNT://DOMAIN/user",
    "LDAP://.../cn=user,..." gibi biçimler. Kısa kullanıcı adı ya da e-posta döner."""
    raw = headers.get("x-authenticated-user")
    if not raw:
        return None
    value = _b64(raw)
    if value.lower().startswith("ldap://"):
        m = re.search(r"(?:cn|uid)=([^,]+)", value, re.I)
        value = m.group(1) if m else ""
    value = re.sub(r"^[a-z]+://", "", value, flags=re.I)
    value = re.split(r"[\\/]", value)[-1].strip().lower()
    return value if _USER.match(value) else None


def proxy_groups(headers: Dict[str, str]) -> List[str]:
    raw = headers.get("x-authenticated-groups")
    if not raw:
        return []
    out = []
    for g in re.split(r"[,;\n]", _b64(raw)):
        g = re.split(r"[\\/]", re.sub(r"^[a-z]+://", "", g.strip(), flags=re.I))[-1].strip()
        m = re.match(r"(?:cn=)?([^,]+)", g, re.I)
        if m and _USER.match(m.group(1)):
            out.append(m.group(1))
    return out


# ---------------- protokol ----------------

async def _read_line(reader: asyncio.StreamReader) -> bytes:
    line = await reader.readuntil(b"\r\n")
    return line[:-2]


async def _read_chunks(reader: asyncio.StreamReader, keep: int, buf: bytearray) -> Tuple[bool, int]:
    """Bir sonraki sıfır uzunluklu parçaya kadar okur. Dönen: (ieof, toplam bayt).
    keep bayttan fazlası okunur ama tutulmaz (bağlantı senkron kalsın)."""
    total = 0
    while True:
        size_line = (await _read_line(reader)).decode("latin-1")
        size_txt, _, ext = size_line.partition(";")
        try:
            size = int(size_txt.strip(), 16)
        except ValueError:
            raise IcapError(400, "Geçersiz parça boyutu")
        if size == 0:
            await _read_line(reader)   # son CRLF (trailer yok)
            return "ieof" in ext, total
        data = await reader.readexactly(size)
        await reader.readexactly(2)
        total += size
        if len(buf) < keep:
            buf.extend(data[: keep - len(buf)])


async def read_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       max_body: int) -> Optional[IcapRequest]:
    """Bir ICAP isteği. Bağlantı kapandıysa None."""
    try:
        first = await _read_line(reader)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None
    while first == b"":        # istekler arasında fazladan CRLF
        first = await _read_line(reader)
    head = [first.decode("latin-1")]
    size = len(first)
    while True:
        line = await _read_line(reader)
        if not line:
            break
        size += len(line)
        if size > MAX_HEADER:
            raise IcapError(400, "Başlıklar çok büyük")
        head.append(line.decode("latin-1"))
    try:
        method, uri, version = head[0].split(" ", 2)
    except ValueError:
        raise IcapError(400, "Geçersiz istek satırı")
    if not version.startswith("ICAP/1."):
        raise IcapError(505, "Desteklenmeyen ICAP sürümü")
    req = IcapRequest(method.upper(), uri, _parse_headers(head[1:]))
    if req.method == "OPTIONS":
        return req
    if req.method != "REQMOD":
        raise IcapError(405, "Yalnızca REQMOD")

    sections = {}
    for item in req.headers.get("encapsulated", "").split(","):
        name, _, offset = item.strip().partition("=")
        if name and offset.isdigit():
            sections[name.strip()] = int(offset)
    if "req-hdr" not in sections:
        raise IcapError(400, "Encapsulated: req-hdr yok")
    end = sections.get("req-body", sections.get("null-body"))
    if end is None or end < sections["req-hdr"] or end > MAX_HEADER:
        raise IcapError(400, "Encapsulated başlığı geçersiz")
    req.http_head = await reader.readexactly(end - sections["req-hdr"])
    if "req-body" not in sections:
        return req

    # 204 kullanılamıyorsa gövde aynen geri gönderileceği için tamamı tutulur
    keep = max_body if req.allow_204 else HARD_BODY_LIMIT
    buf = bytearray()
    ieof, total = await _read_chunks(reader, keep, buf)
    if "preview" in req.headers and not ieof:
        writer.write(b"ICAP/1.0 100 Continue\r\n\r\n")
        await writer.drain()
        _, more = await _read_chunks(reader, keep, buf)
        total += more
    if total > keep and not req.allow_204:
        raise IcapError(500, "Gövde çok büyük ve istemci 204 kabul etmiyor")
    req.body, req.body_truncated = bytes(buf), total > len(buf)
    return req


def _chunk(data: bytes) -> bytes:
    return (f"{len(data):x}\r\n".encode() + data + b"\r\n" if data else b"") + b"0\r\n\r\n"


def _icap_head(status: int, reason: str, istag: str, extra: Dict[str, str]) -> bytes:
    lines = [f"ICAP/1.0 {status} {reason}", f"ISTag: {istag}", "Service: Telveguard"]
    lines += [f"{k}: {v}" for k, v in extra.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def options_response(istag: str, max_connections: int = 200) -> bytes:
    # Preview duyurulmaz: proxy gövdenin tamamını gönderir (karar tüm metne göre verilir)
    return _icap_head(200, "OK", istag, {
        "Methods": "REQMOD", "Allow": "204", "Max-Connections": str(max_connections),
        "Options-TTL": "3600", "Transfer-Preview": "*", "Encapsulated": "null-body=0"})


def no_change_response(req: IcapRequest, istag: str) -> bytes:
    """İstek olduğu gibi geçsin: 204, ya da istemci 204 kabul etmiyorsa isteğin kendisi."""
    if req.allow_204:
        return _icap_head(204, "No Content", istag, {"Encapsulated": "null-body=0"})
    if req.body or "req-body" in req.headers.get("encapsulated", ""):
        enc = f"req-hdr=0, req-body={len(req.http_head)}"
        return _icap_head(200, "OK", istag, {"Encapsulated": enc}) + req.http_head + _chunk(req.body)
    return _icap_head(200, "OK", istag, {"Encapsulated": f"req-hdr=0, null-body={len(req.http_head)}"}) + req.http_head


def block_response(http: HttpRequest, message: str, istag: str) -> bytes:
    """Proxy, isteği hedefe göndermeden bu 403 cevabını kullanıcıya döner. Tarayıcı sayfası
    HTML, uygulamalar / SDK'lar JSON görür (OpenAI ve Anthropic SDK'ları error.message'ı gösterir)."""
    if "text/html" in http.headers.get("accept", ""):
        safe = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        body = (f'<!doctype html><meta charset="utf-8"><title>Telveguard</title>'
                f'<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem">'
                f"<h1>Gönderilmedi</h1><p>{safe}</p></body>").encode("utf-8")
        ctype = "text/html; charset=utf-8"
    else:
        body = json.dumps({"type": "error", "error": {"type": "telveguard_blocked", "code": "blocked",
                                                       "message": message}}, ensure_ascii=False).encode("utf-8")
        ctype = "application/json; charset=utf-8"
    http_head = ("HTTP/1.1 403 Forbidden\r\n"
                 f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                 "Cache-Control: no-store\r\nX-Telveguard-Action: block\r\nConnection: close\r\n\r\n").encode("latin-1")
    return (_icap_head(200, "OK", istag, {"Encapsulated": f"res-hdr=0, res-body={len(http_head)}"})
            + http_head + _chunk(body))


def error_response(status: int, reason: str, istag: str) -> bytes:
    return _icap_head(status, reason.encode("ascii", "replace").decode(), istag, {"Encapsulated": "null-body=0"})


# ---------------- sunucu ----------------

# İnceleme: (istek, site, metin, okunamayan içerik var mı) -> (block mu, kullanıcıya mesaj)
Inspect = Callable[[IcapRequest, HttpRequest, Site, str, bool], Awaitable[Tuple[bool, str]]]


@dataclass
class Settings:
    port: int = 1344
    host: str = "0.0.0.0"
    allowed: List[ipaddress._BaseNetwork] = field(default_factory=list)
    extra_hosts: List[str] = field(default_factory=list)
    max_body: int = 5 * 1024 * 1024
    istag: str = '"telveguard-1"'

    @classmethod
    def from_env(cls, version: str) -> Optional["Settings"]:
        """ICAP_PORT tanımlı değilse kapalı."""
        port = os.getenv("ICAP_PORT", "")
        if not port:
            return None
        allowed = [ipaddress.ip_network(c.strip(), strict=False)
                   for c in os.getenv("ICAP_ALLOWED_CLIENTS", "127.0.0.1/32,::1/128").split(",") if c.strip()]
        extra = [h.strip().lower() for h in os.getenv("ICAP_EXTRA_HOSTS", "").split(",") if h.strip()]
        return cls(int(port), os.getenv("ICAP_HOST", "0.0.0.0"), allowed, extra,
                   int(os.getenv("ICAP_MAX_BODY", str(5 * 1024 * 1024))), f'"telveguard-{version}"')

    def client_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        return any(addr in net for net in self.allowed)


class IcapServer:
    def __init__(self, settings: Settings, inspect: Inspect):
        self.settings, self.inspect = settings, inspect
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        # Her uvicorn worker'ı aynı portu açar (SO_REUSEPORT): çekirdek bağlantıları dağıtır
        self._server = await asyncio.start_server(self._handle, self.settings.host, self.settings.port,
                                                  reuse_port=hasattr(__import__("socket"), "SO_REUSEPORT"))
        log.info("ICAP %s:%s dinleniyor (izinli istemciler: %s)", self.settings.host, self.settings.port,
                 ", ".join(map(str, self.settings.allowed)))

    @property
    def port(self) -> int:
        return self._server.sockets[0].getsockname()[1] if self._server else 0

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = (writer.get_extra_info("peername") or ("",))[0]
        s = self.settings
        try:
            if not s.client_allowed(peer):
                log.warning("ICAP bağlantısı reddedildi: %s (ICAP_ALLOWED_CLIENTS)", peer)
                writer.write(error_response(403, "Forbidden", s.istag))
                return
            while True:
                try:
                    req = await read_request(reader, writer, s.max_body)
                except IcapError as e:
                    writer.write(error_response(e.status, e.reason, s.istag))
                    return
                if req is None:
                    return
                req.client_ip = peer
                writer.write(await self._respond(req))
                await writer.drain()
                if req.headers.get("connection", "").lower() == "close":
                    return
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
            return
        finally:
            try:
                await writer.drain()
                writer.close()
            except ConnectionError:
                pass

    async def _respond(self, req: IcapRequest) -> bytes:
        s = self.settings
        if req.method == "OPTIONS":
            return options_response(s.istag)
        http = req.http()
        site = match_site(http, s.extra_hosts)
        if site is None or not req.body:
            return no_change_response(req, s.istag)
        text, unscannable = extract_text(req.body, http.headers.get("content-type", ""),
                                         http.headers.get("content-encoding", ""))
        try:
            blocked, message = await self.inspect(req, http, site, text, unscannable or req.body_truncated)
        except Exception:   # noqa: BLE001  karar verilemedi: proxy'nin bypass ayarı belirler
            log.exception("ICAP incelemesi başarısız: %s", site.host)
            return error_response(500, "Server Error", s.istag)
        return block_response(http, message, s.istag) if blocked else no_change_response(req, s.istag)
