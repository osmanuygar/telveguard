"""
Anlık bildirim (politika dosyasındaki `notify` bölümü): Slack, Microsoft Teams, genel webhook.

    notify:
      console_url: https://telveguard.sirket.local   # "Konsolda aç" bağlantısı; yoksa TELVEGUARD_PUBLIC_URL
      channels:
        - name: guvenlik-slack
          type: slack                       # slack | teams | webhook
          url_env: SLACK_SECURITY_WEBHOOK_URL
          when:                             # verilen koşulların HEPSİ; liste içinde herhangi biri
            actions: [block]                # block | mask | alert | allow (çıktı kararı dahil)
            rules: ["prompt-injection-*", "kota:*"]   # joker destekli
            entity_in: ["SECRET_*"]         # girdide ya da cevapta sızan türler
            teams: [stajyer]
            sources: [gateway, browser]     # gateway = API isteği, browser = tarayıcı eklentisi
          cooldown_seconds: 300             # aynı ekip + kural için tekrar bildirim aralığı
          include_user: true                # false: mesajda kullanıcı adı yer almaz

Denetim olayı (audit) yazılırken bildirim kuyruğa atılır; gönderim arka planda yapılır,
kullanıcı isteğini bekletmez ve Slack / Teams kesintisi isteği bozmaz.

KVKK: mesajda ham ya da maskeli metin YOKTUR; yalnızca ekip, kullanıcı, model, karar, kural,
veri TÜRLERİ ve olay kimliği. Slack / Teams yurt dışı bir hizmetse kullanıcı adı da yurt
dışına aktarılır: istenmiyorsa include_user: false.

Webhook adresi (Slack / Teams adresinde token gömülüdür) YAML'a yazılmaz: url_env,
"_WEBHOOK_URL" ile biten bir ortam değişkeninin adıdır. Politika dosyası böylece
TELVEGUARD_ADMIN_TOKEN gibi bir sırrı adres diye okuyamaz.

Tekrar bastırma (cooldown) süreç içidir: birden fazla worker / pod varsa aynı olay türü için
pod başına bir bildirim gelebilir.
"""
import asyncio
import fnmatch
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

from telveguard_core.entities import matching_entities
from telveguard_core.policy import SEVERITY

from . import metrics

log = logging.getLogger("telveguard.notify")

TYPES = {"slack", "teams", "webhook"}
SOURCES = {"gateway", "browser"}
WHEN_KEYS = {"actions", "rules", "entity_in", "teams", "sources"}
URL_ENV_RX = re.compile(r"^[A-Z][A-Z0-9_]*_WEBHOOK_URL$")
QUEUE_SIZE = 1000
SEND_TIMEOUT = httpx.Timeout(5, connect=3)
RETRY_DELAY = 1.0

ACTION_TITLES = {"block": "Engellendi", "mask": "Maskelendi", "alert": "Uyarı", "allow": "İzin verildi"}
ACTION_ICONS = {"block": "🚫", "mask": "🛡️", "alert": "⚠️", "allow": "ℹ️"}
DEST_LABELS = {"external": "yurt dışı", "internal": "kurum içi"}


class NotifyError(ValueError):
    pass


@dataclass(frozen=True)
class Channel:
    name: str
    type: str
    url_env: str
    when: Dict[str, Tuple[str, ...]]
    cooldown_seconds: int = 300
    include_user: bool = True

    @property
    def url(self) -> str:
        return os.getenv(self.url_env, "")

    def matches(self, ev: Dict[str, Any]) -> bool:
        w = self.when
        if "actions" in w and effective_action(ev) not in w["actions"]:
            return False
        if "rules" in w and not any(fnmatch.fnmatchcase(r, pat) for r in _rules(ev) for pat in w["rules"]):
            return False
        if "entity_in" in w and not matching_entities(_entities(ev), list(w["entity_in"])):
            return False
        if "teams" in w and not (set(w["teams"]) & (set(ev.get("teams") or []) | {ev.get("team", "")})):
            return False
        if "sources" in w and source_of(ev) not in w["sources"]:
            return False
        return True


def effective_action(ev: Dict[str, Any]) -> str:
    """İstek kararı ile çıktı kararının en kısıtlayıcısı (ör. cevap engellendiyse block)."""
    actions = [ev.get("action") or "allow", ev.get("output_action") or "allow"]
    return max(actions, key=lambda a: SEVERITY.get(a, 0))


def source_of(ev: Dict[str, Any]) -> str:
    return "browser" if ev.get("api_format") == "browser" else "gateway"


def _rules(ev: Dict[str, Any]) -> List[str]:
    return list(ev.get("rules") or []) + list(ev.get("output_rules") or [])


def _entities(ev: Dict[str, Any]) -> set:
    return set(ev.get("entities") or []) | set(ev.get("output_leaked") or [])


def _str_list(where: str, key: str, value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise NotifyError(f"{where}: when.{key} boş olmayan bir liste olmalı")
    return tuple(value)


def _parse(i: int, raw: Any) -> Channel:
    if not isinstance(raw, dict):
        raise NotifyError(f"notify.channels[{i}]: bir nesne olmalı")
    name = str(raw.get("name") or f"channels[{i}]")
    where = f"Bildirim kanalı '{name}'"
    typ = raw.get("type", "webhook")
    if typ not in TYPES:
        raise NotifyError(f"{where}: type şunlardan biri olmalı: {', '.join(sorted(TYPES))}")
    if "url" in raw:
        raise NotifyError(f"{where}: webhook adresi YAML'a yazılmaz; url_env ile ortam değişkeni adı verin")
    url_env = raw.get("url_env") or ""
    if not URL_ENV_RX.match(url_env):
        raise NotifyError(f"{where}: url_env '_WEBHOOK_URL' ile biten büyük harfli bir değişken adı olmalı "
                          "(ör. SLACK_SECURITY_WEBHOOK_URL)")
    # Koşulsuz kanal her isteği bildirir: varsayılan yalnızca engellenenler
    when_raw = raw.get("when") or {"actions": ["block"]}
    if not isinstance(when_raw, dict):
        raise NotifyError(f"{where}: when bir nesne olmalı")
    unknown = set(when_raw) - WHEN_KEYS
    if unknown:
        raise NotifyError(f"{where}: bilinmeyen koşul: {', '.join(sorted(unknown))} "
                          f"(geçerli: {', '.join(sorted(WHEN_KEYS))})")
    when = {k: _str_list(where, k, v) for k, v in when_raw.items()}
    if bad := set(when.get("actions", ())) - set(SEVERITY):
        raise NotifyError(f"{where}: geçersiz aksiyon: {', '.join(sorted(bad))}")
    if bad := set(when.get("sources", ())) - SOURCES:
        raise NotifyError(f"{where}: geçersiz kaynak: {', '.join(sorted(bad))} (gateway | browser)")
    cooldown = raw.get("cooldown_seconds", 300)
    if not isinstance(cooldown, int) or isinstance(cooldown, bool) or not 0 <= cooldown <= 86400:
        raise NotifyError(f"{where}: cooldown_seconds 0-86400 arası bir tamsayı olmalı")
    include_user = raw.get("include_user", True)
    if not isinstance(include_user, bool):
        raise NotifyError(f"{where}: include_user true ya da false olmalı")
    return Channel(name=name, type=typ, url_env=url_env, when=when,
                   cooldown_seconds=cooldown, include_user=include_user)


# ---------------- mesaj biçimleri ----------------

def _slack_escape(text: str) -> str:
    """Ekip / model adı istemciden gelir: "<!channel>" herkesi çağırmasın, bağlantı olmasın."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def summary(ev: Dict[str, Any]) -> str:
    action = effective_action(ev)
    title = ACTION_TITLES.get(action, action)
    if ev.get("output_action") and SEVERITY.get(ev["output_action"], 0) >= SEVERITY.get(ev.get("action"), 0) \
            and ev.get("output_leaked"):
        title += " (model cevabında sızıntı)"
    reason = ev.get("reason") or ""
    return f"{title}: {reason}" if reason else title


def facts(ev: Dict[str, Any], include_user: bool) -> List[Tuple[str, str]]:
    browser = source_of(ev) == "browser"
    out = [("Ekip", ev.get("team") or "–")]
    if include_user:
        out.append(("Kullanıcı", ev.get("user") or "–"))
    dest = DEST_LABELS.get(ev.get("destination"), ev.get("destination") or "–")
    out.append(("Site" if browser else "Model", f"{ev.get('model') or '–'} ({dest})"))
    out.append(("Kaynak", "Tarayıcı eklentisi" if browser else "API isteği"))
    if rules := _rules(ev):
        out.append(("Kural", ", ".join(rules)))
    if entities := sorted(set(ev.get("entities") or [])):
        out.append(("Veri türleri", ", ".join(entities)))
    if leaked := ev.get("output_leaked"):
        out.append(("Cevapta sızan", ", ".join(leaked)))
    if (score := ev.get("injection_score") or 0) >= 0.5:
        out.append(("Injection skoru", f"{score:.2f}"))
    return out


def event_link(console_url: str, ev: Dict[str, Any]) -> str:
    return f"{console_url.rstrip('/')}/xray#olaylar?event={ev['event_id']}" if console_url else ""


def build_payload(ch: Channel, ev: Dict[str, Any], suppressed: int, console_url: str) -> Dict[str, Any]:
    head = f"{ACTION_ICONS.get(effective_action(ev), '')} Telveguard · {summary(ev)}".strip()
    rows = facts(ev, ch.include_user)
    link = event_link(console_url, ev)
    extra = f"Son bildirimden bu yana {suppressed} benzer olay daha oldu." if suppressed else ""

    if ch.type == "slack":
        text = "\n".join(f"*{k}:* {_slack_escape(v)}" for k, v in rows)
        blocks: List[Dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{_slack_escape(head)}*\n{text}"}}]
        context = [f"Olay `{ev['event_id']}`"]
        if link:
            context.append(f"<{link}|Konsolda aç>")
        if extra:
            context.append(extra)
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(context)}]})
        return {"text": head, "blocks": blocks}

    if ch.type == "teams":
        # Teams "Workflows" webhook'u: Adaptive Card ekli mesaj
        body: List[Dict[str, Any]] = [
            {"type": "TextBlock", "text": head, "weight": "Bolder", "size": "Medium", "wrap": True},
            {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in rows]},
            {"type": "TextBlock", "text": f"Olay {ev['event_id']}" + (f" · {extra}" if extra else ""),
             "isSubtle": True, "size": "Small", "wrap": True},
        ]
        card: Dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                "type": "AdaptiveCard", "version": "1.4", "body": body}
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Konsolda aç", "url": link}]
        return {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}

    # Genel webhook (SIEM, SOAR, olay yönetimi): yapılandırılmış alanlar
    event = {k: ev.get(k) for k in (
        "event_id", "ts", "team", "teams", "model", "destination", "action", "output_action", "rules",
        "output_rules", "reason", "entities", "output_leaked", "injection_score", "api_format", "quota")}
    if ch.include_user:
        event["user"] = ev.get("user")
    return {"type": "telveguard.alert", "channel": ch.name, "summary": summary(ev),
            "source": source_of(ev), "severity": effective_action(ev), "suppressed": suppressed,
            "console_url": link or None, "event": event}


# ---------------- gönderim ----------------

@dataclass
class _Cooldown:
    until: float = 0.0
    suppressed: int = 0


@dataclass
class Notifier:
    channels: List[Channel]
    console_url: str = ""
    http: Optional[httpx.AsyncClient] = None
    _queue: Optional[asyncio.Queue] = None
    _worker: Optional[asyncio.Task] = None
    _cooldowns: Dict[Tuple[str, str, str], _Cooldown] = field(default_factory=dict)

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]]) -> "Notifier":
        raw = (cfg or {}).get("notify") or {}
        if not isinstance(raw, dict):
            raise NotifyError("notify bir nesne olmalı (console_url, channels)")
        channels_raw = raw.get("channels") or []
        if not isinstance(channels_raw, list):
            raise NotifyError("notify.channels bir liste olmalı")
        channels = [_parse(i, c) for i, c in enumerate(channels_raw)]
        if len({c.name for c in channels}) != len(channels):
            raise NotifyError("notify.channels: kanal adları benzersiz olmalı")
        console_url = raw.get("console_url") or os.getenv("TELVEGUARD_PUBLIC_URL", "")
        if console_url and not (isinstance(console_url, str) and console_url.startswith(("http://", "https://"))):
            raise NotifyError("notify.console_url (ya da TELVEGUARD_PUBLIC_URL) http(s):// ile başlamalı")
        for c in channels:
            if not c.url:
                log.warning("notify_channel_inactive channel=%s url_env=%s (ortam değişkeni boş)", c.name, c.url_env)
        return cls(channels, console_url)

    @property
    def active(self) -> List[Channel]:
        return [c for c in self.channels if c.url]

    def start(self, http: httpx.AsyncClient):
        self.http = http
        if self.channels:
            self._queue = asyncio.Queue(maxsize=QUEUE_SIZE)
            self._worker = asyncio.create_task(self._run())

    async def stop(self):
        if self._worker:
            # Kuyruktakiler kısa süre içinde gönderilsin; kapanış sonsuza dek beklemesin
            try:
                await asyncio.wait_for(self._queue.join(), timeout=5)
            except asyncio.TimeoutError:
                log.warning("notify_shutdown_dropped pending=%d", self._queue.qsize())
            self._worker.cancel()
            self._worker = None

    def submit(self, ev: Dict[str, Any]):
        """Olayı eşleşen kanallar için kuyruğa atar; beklemez, hata fırlatmaz."""
        if not self._queue:
            return
        for ch in self.active:
            if not ch.matches(ev):
                continue
            suppressed = self._take_cooldown(ch, ev)
            if suppressed is None:
                metrics.NOTIFICATIONS.labels(ch.type, "suppressed").inc()
                continue
            try:
                self._queue.put_nowait((ch, ev, suppressed))
            except asyncio.QueueFull:
                metrics.NOTIFICATIONS.labels(ch.type, "dropped").inc()
                log.error("notify_queue_full channel=%s event_id=%s", ch.name, ev.get("event_id"))

    def _take_cooldown(self, ch: Channel, ev: Dict[str, Any]) -> Optional[int]:
        """Gönderilecekse aradaki bastırılmış olay sayısı, bastırılacaksa None."""
        if ch.cooldown_seconds == 0:
            return 0
        key = (ch.name, ev.get("team", ""), ",".join(_rules(ev)) or effective_action(ev))
        now = time.monotonic()
        state = self._cooldowns.setdefault(key, _Cooldown())
        if now < state.until:
            state.suppressed += 1
            return None
        suppressed, state.suppressed, state.until = state.suppressed, 0, now + ch.cooldown_seconds
        if len(self._cooldowns) > 10_000:  # süresi geçenleri at (bellek sınırı)
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if v.until > now}
        return suppressed

    async def _run(self):
        while True:
            ch, ev, suppressed = await self._queue.get()
            try:
                await self.send(ch, ev, suppressed)
            except Exception:  # işçi hiçbir hatada ölmemeli
                log.exception("notify_worker_error channel=%s", ch.name)
            finally:
                self._queue.task_done()

    async def send(self, ch: Channel, ev: Dict[str, Any], suppressed: int = 0) -> Tuple[bool, str]:
        """Tek kanala gönderir (bir kez yeniden dener). (başarılı mı, açıklama)"""
        url = ch.url
        if not url:
            return False, f"{ch.url_env} tanımlı değil"
        payload = build_payload(ch, ev, suppressed, self.console_url)
        detail = ""
        for attempt in range(2):
            try:
                resp = await self.http.post(url, json=payload, timeout=SEND_TIMEOUT)
                if resp.status_code < 300:
                    metrics.NOTIFICATIONS.labels(ch.type, "sent").inc()
                    return True, f"HTTP {resp.status_code}"
                detail = f"HTTP {resp.status_code}"
                if resp.status_code < 500 and resp.status_code != 429:
                    break  # yanlış adres / yetki: tekrar denemenin anlamı yok
            except httpx.HTTPError as e:
                detail = type(e).__name__
            if attempt == 0:
                await asyncio.sleep(RETRY_DELAY)
        metrics.NOTIFICATIONS.labels(ch.type, "failed").inc()
        # Adreste token olabilir: loga adres değil kanal adı yazılır
        log.error("notify_failed channel=%s event_id=%s error=%s", ch.name, ev.get("event_id"), detail)
        return False, detail

    def describe(self) -> List[Dict[str, Any]]:
        """Arayüz için (adres yok)."""
        return [{"name": c.name, "type": c.type, "active": bool(c.url),
                 "when": {k: list(v) for k, v in c.when.items()},
                 "cooldown_seconds": c.cooldown_seconds} for c in self.channels]


def load(policy_path: str) -> Notifier:
    import yaml

    with open(policy_path, encoding="utf-8") as f:
        return Notifier.from_config(yaml.safe_load(f))
