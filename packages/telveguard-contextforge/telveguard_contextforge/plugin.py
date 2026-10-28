# -*- coding: utf-8 -*-
"""
Telveguard -> IBM ContextForge eklentisi (SPDX-License-Identifier: Apache-2.0)

ContextForge çekirdeğine dokunmadan, cpex eklenti arayüzü üzerinden
Türkçe PII + prompt injection korumasını MCP trafiğine ekler.

Yön farkına dikkat:
  * tool_pre_invoke  : Agent -> araç. Aracın gerçek veriye ihtiyacı olabilir, bu yüzden
                       maskeleme YAPILMAZ. Ama "dış" araca (Slack, web, e-posta) kişisel
                       veri gidiyorsa bu bir sızdırma (exfiltration) girişimidir -> engelle.
  * tool_post_invoke : Araç -> agent/LLM. Sonuçtaki PII maskelenir (dış LLM'e gitmesin),
                       sonuçtaki dolaylı prompt injection engellenir.
  * prompt_pre_fetch : Prompt şablonu argümanları maskelenir, injection engellenir.

Metadata'ya yalnızca sayılar ve tür adları yazılır; ham değerler asla loglanmaz (KVKK).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from fnmatch import fnmatch
from typing import Any, Callable, Dict, List, Literal, Optional, Set, Tuple

from pydantic import BaseModel, Field

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    PromptPrehookPayload,
    PromptPrehookResult,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from cpex.framework.constants import TOOL_METADATA
from telveguard_core import InjectionDetector, TrPiiEngine, entity_matches, matching_entities
from telveguard_core.dictionary import Dictionary, DictionaryError, load as load_dictionary

from .vault import RedisVault

log = logging.getLogger("telveguard.contextforge")

# context.state anahtarı: istek boyunca yer tutucu tutarlılığı
VAULT_KEY = "telveguard_vault"
PLACEHOLDER_RX = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")

# Listeler joker karakter destekler: "SECRET_*" tüm API anahtarı / token / parola türleri,
# "KURUM_*" kurumsal sözlük terimleri (sözlük yüklenmemişse hiç bulunmaz)
DEFAULT_MASK = ["TCKN", "VKN", "IBAN_TR", "CREDIT_CARD", "PHONE_TR", "EMAIL_ADDRESS", "PLATE_TR", "SECRET_*",
                "KURUM_*"]


class ToolAccessRule(BaseModel):
    """Kimin hangi aracı kullanabileceği. teams / users boşsa kural herkese uyar ("*" da olur)."""
    name: str = ""
    teams: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)   # user_id / e-posta, fnmatch
    allow: List[str] = Field(default_factory=list)   # araç adı desenleri
    deny: List[str] = Field(default_factory=list)


class ToolAccessConfig(BaseModel):
    """default=allow: yalnızca deny'lar engeller. default=deny: yalnızca açıkça izin verilen araçlar.
    Deny HER ZAMAN kazanır (kullanıcının herhangi bir ekibine uyan deny, başka ekibin allow'unu ezer)."""
    default: Literal["allow", "deny"] = "allow"
    rules: List[ToolAccessRule] = Field(default_factory=list)


class TelveguardConfig(BaseModel):
    tool_access: ToolAccessConfig = Field(default_factory=ToolAccessConfig)
    mask_entities: List[str] = Field(default_factory=lambda: list(DEFAULT_MASK))
    # Kurum dışına veri taşıyabilen araçlar (fnmatch desenleri)
    external_tools: List[str] = Field(default_factory=lambda: ["slack*", "email*", "web_*", "http_*", "github*"])
    exfil_block_entities: List[str] = Field(
        default_factory=lambda: ["TCKN", "VKN", "IBAN_TR", "CREDIT_CARD", "SECRET_*", "KURUM_*"])
    injection_block_threshold: float = 0.85
    scan_tool_results_for_injection: bool = True
    mask_tool_results: bool = True
    enable_ner: bool = False
    # Kurumsal sözlük. Gateway'den (GET /v1/contextforge/dictionary, token ortam değişkeninde) ya da
    # politika dosyasından (`dictionary` bölümü). İkisi de verilmişse dosya açılışta, gateway üzerine yazar.
    dictionary_gateway_url: str = ""
    dictionary_token_env: str = "TELVEGUARD_CONTEXTFORGE_TOKEN"
    dictionary_file: str = ""
    dictionary_refresh_seconds: int = Field(default=300, ge=30)
    # Araç çağrıları arası yer tutucu vault'u (Redis, kullanıcı kapsamında, değerler şifreli). Redis
    # adresi ortam değişkeninde yoksa tutarlılık tek araç çağrısı içinde kalır.
    vault_redis_url_env: str = "TELVEGUARD_VAULT_REDIS_URL"
    vault_key_env: str = "TELVEGUARD_VAULT_KEY"
    vault_ttl_seconds: int = Field(default=8 * 3600, ge=60)
    # Kurum içi araca giden argümanlardaki yer tutucular gerçek değere çevrilir (dış araca asla)
    unmask_tool_args: bool = True


def _norm_tool(name: str) -> str:
    # Ayraç farkları ("-", ".", "_") eşleşmeyi bozmasın
    return name.lower().replace("-", "_").replace(".", "_")


def _tool_metadata_attr(context: PluginContext, attr: str) -> Optional[str]:
    """ContextForge global_context.metadata["tool"]'a araç modelini koyar (model ya da dict)."""
    meta = (context.global_context.metadata or {}).get(TOOL_METADATA)
    if meta is None:
        return None
    value = meta.get(attr) if isinstance(meta, dict) else getattr(meta, attr, None)
    return value if isinstance(value, str) else None


def _caller(context: PluginContext) -> Dict[str, Any]:
    """Aracı kim çağırıyor? ContextForge kimliği doğrular ve UserContext'e koyar
    (kullanıcı, ekipler, gruplar, bir servis hesabı / agent adına ise service_account)."""
    gc = context.global_context
    uc = gc.user_context
    if uc is not None:
        teams = list(uc.teams or ([uc.team_id] if uc.team_id else []))
        return {"user": uc.user_id, "teams": teams, "groups": list(uc.groups or []),
                "service_account": uc.service_account}
    user = (gc.user.get("email") or gc.user.get("id")) if isinstance(gc.user, dict) else gc.user
    return {"user": user, "teams": [], "groups": [], "service_account": None}


def _walk_strings(value: Any, fn: Callable[[str], str]) -> Any:
    """İç içe dict/list yapılarındaki tüm string'lere fn uygular (MCP content blokları dahil)."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: _walk_strings(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk_strings(v, fn) for v in value]
    return value


def _collect_text(value: Any) -> str:
    parts: List[str] = []
    _walk_strings(value, lambda s: parts.append(s) or s)
    return "\n".join(parts)


class TelveguardPlugin(Plugin):
    """Türkçe PII + prompt injection koruması (ContextForge / cpex)."""

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)
        self._cfg = TelveguardConfig(**(config.config or {}))
        self._pii = TrPiiEngine(enable_ner=self._cfg.enable_ner)
        self._inj = InjectionDetector()
        self._dict_version: Optional[str] = None
        self._dict_checked = 0.0
        self._dict_task: Optional[asyncio.Task] = None
        self._store = RedisVault.from_env(self._cfg.vault_redis_url_env, self._cfg.vault_key_env,
                                          self._cfg.vault_ttl_seconds)
        if self._cfg.dictionary_file:
            # Açılışta okunamayan sözlük sessizce yok sayılmasın: terimler maskesiz gider
            load_dictionary(self._cfg.dictionary_file).install(self._pii)
        if self._cfg.dictionary_gateway_url and not self._cfg.dictionary_gateway_url.startswith(("https://", "http://")):
            raise ValueError("dictionary_gateway_url http(s):// ile başlamalı")

    async def initialize(self) -> None:
        if self._cfg.dictionary_gateway_url:
            await self._refresh_dictionary()

    # ---------- kurumsal sözlük ----------

    def _fetch_dictionary(self) -> Optional[Dict[str, Any]]:
        """None: değişmedi (304). Hata: istisna (çağıran eldeki sözlükle devam eder)."""
        url = self._cfg.dictionary_gateway_url.rstrip("/") + "/v1/contextforge/dictionary"
        headers = {"Authorization": f"Bearer {os.getenv(self._cfg.dictionary_token_env, '')}"}
        if self._dict_version:
            headers["If-None-Match"] = f'"{self._dict_version}"'
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=10) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None
            raise

    async def _refresh_dictionary(self) -> None:
        self._dict_checked = time.monotonic()
        try:
            payload = await asyncio.to_thread(self._fetch_dictionary)
            if payload is None:
                return
            Dictionary.from_config(payload).install(self._pii)
            self._dict_version = payload.get("version")
            log.info("Telveguard: kurumsal sözlük yüklendi (sürüm %s)", self._dict_version)
        except (OSError, ValueError, DictionaryError) as e:   # ağ, JSON, geçersiz sözlük
            log.warning("Telveguard: kurumsal sözlük gateway'den alınamadı, eldekiyle devam: %s", e)

    def _maybe_refresh_dictionary(self) -> None:
        """Süresi dolduysa arka planda yenile; istek beklemez."""
        if not self._cfg.dictionary_gateway_url:
            return
        if time.monotonic() - self._dict_checked < self._cfg.dictionary_refresh_seconds:
            return
        if self._dict_task is not None and not self._dict_task.done():
            return
        self._dict_checked = time.monotonic()
        self._dict_task = asyncio.get_running_loop().create_task(self._refresh_dictionary())

    # ---------- yardımcılar ----------

    def _injection_violation(self, text: str, where: str) -> Optional[PluginViolation]:
        res = self._inj.scan(text)
        if res.score >= self._cfg.injection_block_threshold:
            return PluginViolation(
                reason="Olası prompt injection",
                description=f"Telveguard: {where} içinde talimat geçersiz kılma girişimi tespit edildi.",
                code="TELVEGUARD_PROMPT_INJECTION",
                details={"score": res.score, "engine": res.engine, "where": where},
            )
        return None

    @staticmethod
    def _vault(context: PluginContext) -> Dict[str, str]:
        """İstek boyunca ortak yer tutucu vault'u (yer tutucu -> orijinal).

        Eklentiye özel context.state'te tutulur; global_context.state diğer
        eklentilerle paylaşıldığı için ham değerler oraya KONMAZ. Çağıran taraf
        invoke_hook'un döndürdüğü context tablosunu sonraki çağrıya geri verirse
        (local_contexts) aynı TCKN tüm araç çağrılarında aynı [TCKN_n]'i alır;
        vermezse tutarlılık tek çağrı içinde kalır. Vault istekle birlikte ölür.

        Not (ContextForge v1.0.10'da doğrulandı): her MCP tools/call ayrı bir HTTP
        isteğidir ve pre hook local_contexts=None ile çağrılır; yani bu vault'la
        tutarlılık tek araç çağrısı (pre -> post) içindedir. Çağrılar arası tutarlılık
        için Redis vault'u (vault.py, `vault_redis_url_env`); bu yalnızca Redis yokken
        ya da çağıran anonimken kullanılır.
        """
        return context.state.setdefault(VAULT_KEY, {})

    def _scope(self, context: PluginContext) -> Optional[str]:
        """Kalıcı vault kapsamı: kimliği bilinen kullanıcı. Anonim çağrıda yok (anonim kullanıcılar
        birbirinin değerini geri açabilirdi)."""
        if self._store is None:
            return None
        user = _caller(context)["user"]
        return self._store.scope(context.global_context.tenant_id, str(user)) if user else None

    async def _mask(self, value: Any, context: PluginContext) -> Tuple[Any, Dict[str, int]]:
        scope = self._scope(context)
        if scope is None:
            return self._mask_with(value, self._vault(context), None)
        # Redis senkron istemci: olay döngüsü beklemesin. Redis'e ulaşılamazsa istisna yükselir;
        # çağıran engeller (çağrı içi numara, Redis'teki başka bir değerin numarasıyla çakışırsa
        # sonraki geri açma kurum içi araca YANLIŞ kişinin verisini verirdi)
        return await asyncio.to_thread(self._mask_with, value, {}, scope)

    def _mask_with(self, value: Any, vault: Dict[str, str], scope: Optional[str]) -> Tuple[Any, Dict[str, int]]:
        counts: Dict[str, int] = {}

        def fn(s: str) -> str:
            if scope is not None:
                # Numara Redis'ten: aynı kullanıcıda aynı değer her çağrıda aynı yer tutucu
                for f in self._pii.analyze(s):
                    if entity_matches(f.entity, self._cfg.mask_entities):
                        vault.setdefault(self._store.assign(scope, f.entity, s[f.start:f.end]), s[f.start:f.end])
            m = self._pii.mask(s, self._cfg.mask_entities, vault)
            for f in m.findings:
                if entity_matches(f.entity, self._cfg.mask_entities):
                    counts[f.entity] = counts.get(f.entity, 0) + 1
            return m.text

        return _walk_strings(value, fn), counts

    def _unmask_with(self, value: Any, scope: str) -> Tuple[Any, int]:
        n = 0

        def sub(m: "re.Match[str]") -> str:
            nonlocal n
            original = self._store.lookup(scope, m.group(0))
            if original is None:      # bu kullanıcının vault'unda yok: olduğu gibi
                return m.group(0)
            n += 1
            return original

        return _walk_strings(value, lambda s: PLACEHOLDER_RX.sub(sub, s)), n

    @staticmethod
    def _vault_violation() -> PluginViolation:
        return PluginViolation(
            reason="Yer tutucu deposuna ulaşılamadı",
            description="Telveguard: kişisel veri maskelenemedi (vault erişilemez); çıktı gönderilmedi.",
            code="TELVEGUARD_VAULT_UNAVAILABLE",
            details={},
        )

    def _is_external(self, tool_name: str, context: PluginContext) -> bool:
        """ContextForge araç adını "<gateway>-<slug>" yapar ve "_" -> "-" çevirir
        (email_send -> mockcrm-email-send); bu yüzden "email*" deseni ham adla eşleşmez.
        Hem orijinal ad (metadata) hem de önekli ad normalize edilip denenir; önekli
        adda desen herhangi bir ayraçtan sonra da eşleşebilir (şüphede engelle)."""
        names, _ = self._tool_names(tool_name, context)
        for pattern in (_norm_tool(p) for p in self._cfg.external_tools):
            for name in names:
                if fnmatch(name, pattern) or fnmatch(name, f"*_{pattern}"):
                    return True
        return False

    @staticmethod
    def _tool_names(tool_name: str, context: PluginContext) -> Tuple[Set[str], Optional[str]]:
        names = {_norm_tool(tool_name)}
        original = _tool_metadata_attr(context, "original_name")
        if original:
            names.add(_norm_tool(original))
        return names, _norm_tool(original) if original else None

    def _access_violation(self, tool_name: str, context: PluginContext) -> Optional[PluginViolation]:
        """Araç izin listesi. Eşleştirme bilerek asimetrik:
          deny  -> önekli ad dahil geniş eşleşme (şüphede engelle; "*_github*" gibi)
          allow -> yalnızca orijinal ad (yoksa tam ad) ile tam desen: "crm_*" izni,
                   adında "_crm_" geçen alakasız bir aracı açmasın."""
        acc = self._cfg.tool_access
        if not acc.rules and acc.default == "allow":
            return None
        caller = _caller(context)
        who = set(caller["teams"]) | set(caller["groups"])
        names, original = self._tool_names(tool_name, context)
        allow_name = original or _norm_tool(tool_name)

        def applies(rule: ToolAccessRule) -> bool:
            team_ok = not rule.teams or "*" in rule.teams or bool(set(rule.teams) & who)
            user_ok = not rule.users or any(fnmatch((caller["user"] or "").lower(), u.lower()) for u in rule.users)
            return team_ok and user_ok

        applicable = [r for r in acc.rules if applies(r)]
        for rule in applicable:
            for pattern in (_norm_tool(p) for p in rule.deny):
                if any(fnmatch(n, pattern) or fnmatch(n, f"*_{pattern}") for n in names):
                    return self._denied(tool_name, caller, rule.name or "deny")
        if acc.default == "deny" and not any(
                fnmatch(allow_name, _norm_tool(p)) for r in applicable for p in r.allow):
            return self._denied(tool_name, caller, "default-deny")
        return None

    @staticmethod
    def _denied(tool_name: str, caller: Dict[str, Any], rule: str) -> PluginViolation:
        return PluginViolation(
            reason="Araç kullanım izni yok",
            description=f"Telveguard: '{tool_name}' aracını kullanma izniniz yok ({rule}).",
            code="TELVEGUARD_TOOL_DENIED",
            details={"tool": tool_name, "rule": rule, "user": caller["user"], "teams": caller["teams"],
                     "service_account": caller["service_account"]},
        )

    # ---------- hook'lar ----------

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        self._maybe_refresh_dictionary()
        args = payload.args or {}
        if v := self._injection_violation(_collect_text(args), "prompt argümanları"):
            return PromptPrehookResult(continue_processing=False, violation=v)
        try:
            masked, counts = await self._mask(args, context)
        except Exception as e:   # redis.exceptions.* + zaman aşımı
            log.warning("Telveguard: vault erişilemez: %s", e)
            return PromptPrehookResult(continue_processing=False, violation=self._vault_violation())
        if counts:
            return PromptPrehookResult(
                modified_payload=PromptPrehookPayload(prompt_id=payload.prompt_id, args=masked),
                metadata={"telveguard": {"masked": counts}},
            )
        return PromptPrehookResult(continue_processing=True)

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        self._maybe_refresh_dictionary()
        # İzin önce: yetkisiz araç için argüman bile taranmaz
        if v := self._access_violation(payload.name, context):
            return ToolPreInvokeResult(continue_processing=False, violation=v)
        text = _collect_text(payload.args or {})
        if v := self._injection_violation(text, f"'{payload.name}' araç argümanları"):
            return ToolPreInvokeResult(continue_processing=False, violation=v)

        if self._is_external(payload.name, context):
            found: Set[str] = {f.entity for f in self._pii.analyze(text)}
            leaked = sorted(matching_entities(found, self._cfg.exfil_block_entities))
            if leaked:
                return ToolPreInvokeResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason="Kişisel veri sızdırma girişimi",
                        description=f"Telveguard: '{payload.name}' kurum dışı bir araç; {', '.join(leaked)} gönderilemez.",
                        code="TELVEGUARD_PII_EXFILTRATION",
                        details={"tool": payload.name, "entities": leaked, "user": _caller(context)["user"]},
                    ),
                )
        # Agent kimliği: izin verilen çağrıda da kim / hangi servis hesabı adına
        caller = _caller(context)
        meta: Dict[str, Any] = {"caller": caller["user"], "teams": caller["teams"],
                                "service_account": caller["service_account"]}
        # Kurum içi araç önceki çağrıdan gelen [TCKN_1]'in gerçek değerini alır. Dış araçta geri açma
        # YOK: oraya yalnızca yer tutucu gider (sızdırma kontrolü yukarıda yer tutucuyu görür)
        scope = self._scope(context)
        if (scope is not None and self._cfg.unmask_tool_args and not self._is_external(payload.name, context)
                and PLACEHOLDER_RX.search(text)):
            try:
                args, n = await asyncio.to_thread(self._unmask_with, payload.args or {}, scope)
            except Exception as e:   # Redis yok: araç yer tutucuyla çalışır (veri sızmaz, yanlış veri de gitmez)
                log.warning("Telveguard: vault erişilemez, argümanlar geri açılmadı: %s", e)
                meta["unmask"] = "vault_unavailable"
            else:
                if n:
                    meta["unmasked"] = n
                    return ToolPreInvokeResult(modified_payload=payload.model_copy(update={"args": args}),
                                               metadata={"telveguard": meta})
        return ToolPreInvokeResult(continue_processing=True, metadata={"telveguard": meta})

    async def tool_post_invoke(self, payload: ToolPostInvokePayload, context: PluginContext) -> ToolPostInvokeResult:
        self._maybe_refresh_dictionary()
        if self._cfg.scan_tool_results_for_injection:
            if v := self._injection_violation(_collect_text(payload.result), f"'{payload.name}' araç çıktısı"):
                return ToolPostInvokeResult(continue_processing=False, violation=v)

        if self._cfg.mask_tool_results:
            try:
                masked, counts = await self._mask(payload.result, context)
            except Exception as e:   # redis.exceptions.* + zaman aşımı
                log.warning("Telveguard: vault erişilemez: %s", e)
                return ToolPostInvokeResult(continue_processing=False, violation=self._vault_violation())
            if counts:
                return ToolPostInvokeResult(
                    modified_payload=ToolPostInvokePayload(name=payload.name, result=masked),
                    metadata={"telveguard": {"masked": counts, "tool": payload.name}},
                )
        return ToolPostInvokeResult(continue_processing=True)
