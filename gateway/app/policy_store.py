"""
Konsoldan politika yönetimi: sürümler ClickHouse'ta, değişiklik pod'lara yeniden başlatmadan yayılır.

Yalnızca kurallar düzenlenir (EDITABLE_KEYS): default_action, mode, rules, output_rules, routing.
Sağlayıcılar, kurumsal sözlük, bildirim kanalları, kota ve fiyatlar ConfigMap'teki politika
dosyasından gelmeye devam eder (sır / dosya yolu içerir, yeniden kurulum ister). Çalışan
politika = ConfigMap dosyası + yayındaki sürümün kuralları.

Saklama (ekleme yapılır; güncelleme ve silme yok):
  policy_versions  her sürümün içeriği, yazanı, gerekçesi
  policy_events    sürümün başına gelenler: created | approved | rejected | applied | emergency
Bir sürümün durumu son olayından, yayındaki sürüm son "approved / applied / emergency"
olayından çıkar. Geri alma = eski (onaylı) bir sürümün yeniden "applied" olması.

Dört göz: sürümü yazan onaylayamaz (POLICY_FOUR_EYES=0 ile kapatılır). Acil durumda yazan
gerekçe yazarak kendi sürümünü yayına alabilir ("emergency", kayıtta ayrı görünür).

ClickHouse'ta işlem (transaction) olmadığından sürüm numarası verme ve durum geçişleri bir
kilitle sıralanır: REDIS_URL varsa Redis (tüm pod'lar), yoksa süreç içi kilit (tek pod).
Pod'lar yayındaki sürümü POLICY_STORE_POLL_SECONDS'ta bir sorar; değiştiyse yeni motoru kurar.
ClickHouse'a ulaşılamazsa gateway bildiği son politikayla (açılışta ConfigMap) çalışmayı sürdürür.
"""
import asyncio
import difflib
import hashlib
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple

import yaml

from telveguard_core.policy import PolicyEngine

from .xray import ClickHouse, ClickHouseError

log = logging.getLogger("telveguard.policy_store")

EDITABLE_KEYS = ("default_action", "mode", "rules", "output_rules", "routing")
ACTIVATING = ("approved", "applied", "emergency")
MAX_CONTENT = 512 * 1024
LOCK_KEY = "telveguard:policy:lock"


class StoreError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ---------------- içerik ----------------

def editable_part(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return {k: cfg[k] for k in EDITABLE_KEYS if k in cfg}


def merge(base: Dict[str, Any], editable: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in base.items() if k not in EDITABLE_KEYS}
    out.update(editable)
    return out


def to_yaml(editable: Dict[str, Any]) -> str:
    return yaml.safe_dump(editable, allow_unicode=True, sort_keys=False, width=100)


def _blocks(raw: str) -> Tuple[List[Tuple[str, List[str]]], List[str]]:
    """Üst düzey anahtar blokları (hemen üstündeki yorumlar o anahtara ait) ve sondaki satırlar."""
    blocks: List[Tuple[str, List[str]]] = []
    pending: List[str] = []
    for line in raw.splitlines():
        top = line[:1] not in ("", " ", "\t", "#", "-") and ":" in line
        if top:
            blocks.append((line.split(":", 1)[0].strip(), pending + [line]))
            pending = []
        elif not line.strip() or line.lstrip().startswith("#") and not line.startswith((" ", "\t")):
            pending.append(line)
        elif blocks:
            blocks[-1][1].extend(pending + [line])
            pending = []
    return blocks, pending


def editable_text(raw: str) -> str:
    """ConfigMap dosyasından yalnızca kural bölümlerinin METNİ (açıklama satırlarıyla):
    ilk taslak güvenlik ekibinin yorumlarını kaybetmesin. Metin aynı sonucu vermiyorsa
    yeniden üretilmiş YAML döner."""
    expected = editable_part(yaml.safe_load(raw) or {})
    blocks, _ = _blocks(raw)
    text = "\n".join(line for key, lines in blocks if key in EDITABLE_KEYS for line in lines).strip("\n") + "\n"
    try:
        if yaml.safe_load(text) == expected:
            return text
    except yaml.YAMLError:
        pass
    return to_yaml(expected)


def with_rules(base_raw: str, content: str) -> str:
    """ConfigMap dosyasının metni, kural bölümleri sürümün metniyle değiştirilmiş (Git'e yazılan,
    dağıtılabilir tam politika). Her bölüm dosyadaki yerinde değişir (fark küçük kalır); diğer
    bölümler ve yorumları olduğu gibi kalır."""
    blocks, tail = _blocks(base_raw)
    new_blocks, new_tail = _blocks(content)
    new = dict(new_blocks)
    out: List[str] = []
    used = set()
    last_editable = None
    for key, lines in blocks:
        if key in EDITABLE_KEYS:
            if key in new:
                out.extend(new[key])
                used.add(key)
            last_editable = len(out)
            continue
        out.extend(lines)
    extra = [line for key, lines in new_blocks if key not in used for line in lines]
    if extra:
        at = len(out) if last_editable is None else last_editable
        out[at:at] = ([""] if at else []) + extra
    text = "\n".join(out + tail + new_tail).rstrip("\n") + "\n"
    expected = merge(yaml.safe_load(base_raw) or {}, yaml.safe_load(content) or {})
    try:
        if yaml.safe_load(text) == expected:
            return text
    except yaml.YAMLError:
        pass
    return to_yaml(expected)


def parse(content: str, base: Dict[str, Any]) -> Tuple[Dict[str, Any], PolicyEngine]:
    """Konsoldan gelen YAML: yalnızca kural anahtarları; motor kurulabiliyorsa geçerli."""
    if len(content.encode("utf-8")) > MAX_CONTENT:
        raise StoreError(400, "Politika çok büyük (en fazla 512 KB)")
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f" (satır {mark.line + 1})" if mark else ""
        problem = str(getattr(e, "problem", None) or e)
        hint = ("girinti ya da yapı hatası; aynı düzeydeki satırlar aynı hizada olmalı"
                if "expected" in problem or "mapping" in problem else
                "kapanmamış tırnak" if "quoted" in problem or "quote" in problem else
                "sekme karakteri; girinti için boşluk kullanın" if "\\t" in problem or "tab" in problem else problem)
        raise StoreError(400, f"YAML okunamadı{where}: {hint}")
    if not isinstance(data, dict):
        raise StoreError(400, "Politika bir YAML sözlüğü olmalı (rules: ...)")
    extra = sorted(set(data) - set(EDITABLE_KEYS))
    if extra:
        raise StoreError(400, f"Konsoldan yalnızca {', '.join(EDITABLE_KEYS)} düzenlenir; "
                              f"{', '.join(extra)} ConfigMap'teki politika dosyasında kalır")
    try:
        engine = PolicyEngine(config=merge(base, data))
    except (ValueError, KeyError, TypeError) as e:
        raise StoreError(400, str(e))
    return data, engine


def rules_diff(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Konsoldaki kural listesi: taslaktaki (ve silinen) her kural, yayındakine göre durumu
    (added | changed | removed | same) ve genel ayarların değişimi."""
    def index(data):
        mode = data.get("mode", "enforce")
        return {(kind, r.get("name")): {**r, "mode": r.get("mode", mode)}
                for kind in ("rules", "output_rules", "routing") for r in (data.get(kind) or [])}
    before, after = index(old), index(new)
    out = []
    for key, rule in after.items():
        status = "added" if key not in before else "same" if before[key] == rule else "changed"
        out.append(_rule_row(key, rule, status, before.get(key)))
    for key, rule in before.items():
        if key not in after:
            out.append(_rule_row(key, rule, "removed"))
    settings = {k: {"before": old.get(k, d), "after": new.get(k, d)}
                for k, d in (("default_action", "allow"), ("mode", "enforce"))}
    counts = {s: sum(1 for r in out if r["status"] == s) for s in ("added", "changed", "removed")}
    return {"rules": out, "settings": settings, "counts": counts}


def _rule_row(key, rule: Dict[str, Any], status: str, before: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    kind = {"output_rules": "output", "routing": "routing"}.get(key[0], "input")
    row = {"kind": kind, "name": key[1], "status": status,
           "action": "route" if kind == "routing" else rule.get("action"), "mode": rule.get("mode"),
           "when": rule.get("when") or {}, "message": rule.get("message", "")}
    if kind == "routing":
        row["to"] = rule.get("to")
    if before is not None and status == "changed":
        row["before"] = {"action": "route" if kind == "routing" else before.get("action"),
                         "mode": before.get("mode"), "when": before.get("when") or {}}
    return row


def diff(old: str, new: str, old_name: str, new_name: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        old_name, new_name, n=3))


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------- kilit ----------------

class Lock:
    """Sürüm numarası ve durum geçişleri için kısa süreli kilit."""

    def __init__(self, redis_url: str = "", password: str = ""):
        self._local = asyncio.Lock()
        self._redis = None
        if redis_url:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(redis_url, password=password or None, socket_timeout=2,
                                            socket_connect_timeout=2, decode_responses=True)

    @asynccontextmanager
    async def hold(self, wait: float = 5.0):
        async with self._local:
            if not self._redis:
                yield
                return
            token, deadline = uuid.uuid4().hex, time.monotonic() + wait
            try:
                while not await self._redis.set(LOCK_KEY, token, nx=True, px=60000):
                    if time.monotonic() > deadline:
                        raise StoreError(409, "Başka bir politika işlemi sürüyor; birkaç saniye sonra yeniden deneyin")
                    await asyncio.sleep(0.1)
            except StoreError:
                raise
            except Exception as e:   # noqa: BLE001  redis.exceptions.*
                raise StoreError(503, f"Kilit alınamadı (Redis): {type(e).__name__}")
            try:
                yield
            finally:
                try:
                    if await self._redis.get(LOCK_KEY) == token:
                        await self._redis.delete(LOCK_KEY)
                except Exception:   # noqa: BLE001  süresi dolunca kendiliğinden açılır
                    pass

    async def close(self):
        if self._redis:
            await self._redis.aclose()


# ---------------- depo ----------------

def _status(events: List[Dict[str, Any]]) -> str:
    """Sürümün son karar olayı: pending | approved | rejected (applied / emergency = approved)."""
    status = "pending"
    for e in events:
        if e["event"] == "rejected":
            status = "rejected"
        elif e["event"] in ACTIVATING:
            status = "approved"
    return status


class PolicyStore:
    def __init__(self, ch: ClickHouse, lock: Lock, four_eyes: bool = True, quorum: str = ""):
        self.ch, self.lock, self.four_eyes = ch, lock, four_eyes
        # Kopyalı ClickHouse: yazma tüm kopyalara ulaşsın, okuma en son yazılanı görsün
        self.write_settings = {"insert_quorum": quorum} if quorum else {}
        self.read_settings = {"select_sequential_consistency": "1"} if quorum else {}

    @classmethod
    def from_env(cls, http) -> Optional["PolicyStore"]:
        if os.getenv("POLICY_STORE", "") != "clickhouse":
            return None
        url = os.getenv("CLICKHOUSE_URL")
        if not url:
            raise RuntimeError("POLICY_STORE=clickhouse için CLICKHOUSE_URL gerekli")
        # Röntgen kullanıcısı yalnızca okuma yetkili olmalı: yazma ayrı kullanıcıyla (yalnızca policy_* tabloları)
        ch = ClickHouse(http, url, os.getenv("POLICY_STORE_CLICKHOUSE_USER", os.getenv("CLICKHOUSE_USER", "default")),
                        os.getenv("POLICY_STORE_CLICKHOUSE_PASSWORD", os.getenv("CLICKHOUSE_PASSWORD", "")),
                        os.getenv("CLICKHOUSE_DB", "telveguard"))
        return cls(ch, Lock(os.getenv("REDIS_URL", ""), os.getenv("REDIS_PASSWORD", "")),
                   os.getenv("POLICY_FOUR_EYES", "1") != "0", os.getenv("POLICY_STORE_INSERT_QUORUM", ""))

    async def _query(self, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        try:
            return await self.ch.query(sql, params or {}, settings=self.read_settings)
        except ClickHouseError as e:
            raise StoreError(503, str(e))

    async def _insert(self, table: str, rows: List[Dict[str, Any]]) -> None:
        try:
            await self.ch.insert(table, rows, settings=self.write_settings)
        except ClickHouseError as e:
            raise StoreError(503, str(e))

    async def _events(self, version: Optional[int] = None) -> List[Dict[str, Any]]:
        where = "WHERE version = {v:UInt32}" if version is not None else ""
        return await self._query(
            f"SELECT version, toString(ts) AS ts, event, actor, actor_via, comment FROM policy_events {where} "
            "ORDER BY ts, event_id", {"v": version} if version is not None else {})

    async def active(self) -> Optional[Dict[str, Any]]:
        """Yayındaki sürüm (içerikle) ya da hiç yayına alınmamışsa None."""
        rows = await self._query(
            "SELECT version FROM policy_events WHERE event IN ('approved', 'applied', 'emergency') "
            "ORDER BY ts DESC, event_id DESC LIMIT 1")
        if not rows:
            return None
        return await self.get(int(rows[0]["version"]), with_events=False)

    async def get(self, version: int, with_events: bool = True) -> Dict[str, Any]:
        rows = await self._query(
            "SELECT version, toString(created_at) AS created_at, author, author_via, comment, content, "
            "content_sha256, base_version FROM policy_versions WHERE version = {v:UInt32} LIMIT 1", {"v": version})
        if not rows:
            raise StoreError(404, f"Sürüm {version} yok")
        row = rows[0]
        row["version"] = int(row["version"])
        if with_events:
            row["events"] = await self._events(version)
            row["status"] = _status(row["events"])
        return row

    async def list(self, limit: int = 100) -> List[Dict[str, Any]]:
        versions = await self._query(
            "SELECT version, toString(created_at) AS created_at, author, author_via, comment, content_sha256, "
            "base_version FROM policy_versions ORDER BY version DESC LIMIT {n:UInt32}", {"n": limit})
        events: Dict[int, List[Dict[str, Any]]] = {}
        for e in await self._events():
            events.setdefault(int(e["version"]), []).append(e)
        for v in versions:
            v["version"] = int(v["version"])
            v["events"] = events.get(v["version"], [])
            v["status"] = _status(v["events"])
        return versions

    async def event(self, version: int, event: str, actor: str, via: str, comment: str) -> None:
        await self._insert("policy_events", [{
            "event_id": str(uuid.uuid4()), "version": version, "ts": int(time.time() * 1000),
            "event": event, "actor": actor, "actor_via": via, "comment": comment}])

    async def create(self, content: str, author: str, via: str, comment: str, base_version: int) -> int:
        async with self.lock.hold():
            rows = await self._query("SELECT max(version) AS v FROM policy_versions")
            version = int((rows[0] if rows else {}).get("v") or 0) + 1
            await self._insert("policy_versions", [{
                "version": version, "created_at": int(time.time() * 1000), "author": author,
                "author_via": via, "comment": comment, "content": content,
                "content_sha256": sha256(content), "base_version": base_version}])
            await self.event(version, "created", author, via, comment)
        return version

    async def transition(self, version: int, action: str, actor: str, via: str, comment: str,
                         emergency: bool = False, before_commit=None) -> Dict[str, Any]:
        """approve | reject | apply. Kilit altında durum yeniden okunur (iki kişi aynı anda onaylarsa
        ikincisi "zaten onaylandı" görür)."""
        async with self.lock.hold():
            v = await self.get(version)
            status, author = v["status"], v["author"]
            same_person = actor.strip().lower() == author.strip().lower()
            if action == "reject":
                if status != "pending":
                    raise StoreError(409, f"Sürüm {version} bekleyen bir sürüm değil ({status})")
                event = "rejected"
            elif action == "approve":
                if status != "pending":
                    raise StoreError(409, f"Sürüm {version} bekleyen bir sürüm değil ({status})")
                if same_person and self.four_eyes:
                    if not emergency:
                        raise StoreError(403, "Dört göz kuralı: sürümü yazan onaylayamaz. Başka bir yönetici "
                                              "onaylamalı ya da acil yayın (gerekçeyle) seçilmeli.")
                    if len(comment.strip()) < 10:
                        raise StoreError(400, "Acil yayın için gerekçe zorunlu (en az 10 karakter)")
                    event = "emergency"
                else:
                    event = "approved"
            elif action == "apply":
                # Geri alma / yeniden yayın: yalnızca daha önce onaylanmış içerik
                if status != "approved":
                    raise StoreError(409, f"Yalnızca onaylanmış sürümler yeniden yayına alınabilir ({status})")
                if len(comment.strip()) < 3:
                    raise StoreError(400, "Geri alma için gerekçe yazın")
                event = "applied"
            else:
                raise StoreError(400, f"Bilinmeyen işlem: {action}")
            if before_commit is not None:
                # Ör. Git'e yazma zorunluysa: başarısızsa olay yazılmaz, sürüm yayına girmez
                await before_commit(v, event)
            await self.event(version, event, actor, via, comment)
        return {"version": version, "event": event}


# ---------------- çalışan politika ----------------

class Runtime:
    """Gateway'deki çalışan politika: ConfigMap tabanı + yayındaki sürüm. Sürüm değişince motor
    yeniden kurulur ve app.state.policy atomik olarak değişir (istek ortasında yarım politika yok)."""

    def __init__(self, state, base_text: str, store: Optional[PolicyStore]):
        self.state, self.store = state, store
        self.base_text = base_text
        self.base = yaml.safe_load(base_text) or {}
        self.base_content = editable_text(base_text)
        self.content = self.base_content          # yayındaki kural metni (konsolda düzenlenen)
        self.version: Optional[int] = None      # None: ConfigMap
        self.loaded_at = time.time()
        self.last_error = ""
        self._task: Optional[asyncio.Task] = None

    async def refresh(self) -> bool:
        """Yayındaki sürüm değiştiyse yükler. Hata: bilinen politika korunur."""
        if not self.store:
            return False
        try:
            active = await self.store.active()
        except StoreError as e:
            self.last_error = e.message
            return False
        version = active["version"] if active else None
        if version == self.version:
            self.last_error = ""
            return False
        try:
            if active:
                _, engine = parse(active["content"], self.base)
            else:
                engine = PolicyEngine(config=self.base)
        except StoreError as e:
            # Kayıtlı sürüm bu pod'un tabanıyla geçersizse (ör. ConfigMap değişti) eskisi korunur
            self.last_error = f"Sürüm {version} yüklenemedi: {e.message}"
            log.error(self.last_error)
            return False
        self.state.policy, self.version, self.loaded_at, self.last_error = engine, version, time.time(), ""
        self.content = active["content"] if active else self.base_content
        log.info("politika sürümü yüklendi: %s", version or "ConfigMap")
        return True

    async def start(self, interval: float) -> None:
        if not self.store:
            return
        try:
            await asyncio.wait_for(self.refresh(), timeout=10)
        except asyncio.TimeoutError:
            self.last_error = "Açılışta politika deposuna ulaşılamadı; ConfigMap politikası kullanılıyor"
            log.warning(self.last_error)

        async def loop():
            while True:
                await asyncio.sleep(interval)
                try:
                    await self.refresh()
                except Exception:   # noqa: BLE001  döngü ölmesin
                    log.exception("politika yenilenemedi")
        self._task = asyncio.create_task(loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        if self.store:
            await self.store.lock.close()

    def describe(self) -> Dict[str, Any]:
        return {"enabled": bool(self.store), "version": self.version,
                "source": f"sürüm {self.version}" if self.version else "ConfigMap",
                "loaded_at": int(self.loaded_at * 1000), "error": self.last_error,
                "four_eyes": bool(self.store and self.store.four_eyes)}
