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

from fnmatch import fnmatch
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

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

# context.state anahtarı: istek boyunca yer tutucu tutarlılığı
VAULT_KEY = "telveguard_vault"

# Listeler joker karakter destekler: "SECRET_*" tüm API anahtarı / token / parola türleri
DEFAULT_MASK = ["TCKN", "VKN", "IBAN_TR", "CREDIT_CARD", "PHONE_TR", "EMAIL_ADDRESS", "PLATE_TR", "SECRET_*"]


class TelveguardConfig(BaseModel):
    mask_entities: List[str] = Field(default_factory=lambda: list(DEFAULT_MASK))
    # Kurum dışına veri taşıyabilen araçlar (fnmatch desenleri)
    external_tools: List[str] = Field(default_factory=lambda: ["slack*", "email*", "web_*", "http_*", "github*"])
    exfil_block_entities: List[str] = Field(default_factory=lambda: ["TCKN", "VKN", "IBAN_TR", "CREDIT_CARD", "SECRET_*"])
    injection_block_threshold: float = 0.85
    scan_tool_results_for_injection: bool = True
    mask_tool_results: bool = True
    enable_ner: bool = False


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
        isteğidir ve pre hook local_contexts=None ile çağrılır; yani ContextForge'da
        tutarlılık tek araç çağrısı (pre -> post) içindedir, çağrılar arası değil.
        """
        return context.state.setdefault(VAULT_KEY, {})

    def _mask(self, value: Any, context: PluginContext) -> Tuple[Any, Dict[str, int]]:
        counts: Dict[str, int] = {}
        vault = self._vault(context)

        def fn(s: str) -> str:
            m = self._pii.mask(s, self._cfg.mask_entities, vault)
            for f in m.findings:
                if entity_matches(f.entity, self._cfg.mask_entities):
                    counts[f.entity] = counts.get(f.entity, 0) + 1
            return m.text

        return _walk_strings(value, fn), counts

    def _is_external(self, tool_name: str, context: PluginContext) -> bool:
        """ContextForge araç adını "<gateway>-<slug>" yapar ve "_" -> "-" çevirir
        (email_send -> mockcrm-email-send); bu yüzden "email*" deseni ham adla eşleşmez.
        Hem orijinal ad (metadata) hem de önekli ad normalize edilip denenir; önekli
        adda desen herhangi bir ayraçtan sonra da eşleşebilir (şüphede engelle)."""
        names = {_norm_tool(tool_name)}
        original = _tool_metadata_attr(context, "original_name")
        if original:
            names.add(_norm_tool(original))
        for pattern in (_norm_tool(p) for p in self._cfg.external_tools):
            for name in names:
                if fnmatch(name, pattern) or fnmatch(name, f"*_{pattern}"):
                    return True
        return False

    # ---------- hook'lar ----------

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        args = payload.args or {}
        if v := self._injection_violation(_collect_text(args), "prompt argümanları"):
            return PromptPrehookResult(continue_processing=False, violation=v)
        masked, counts = self._mask(args, context)
        if counts:
            return PromptPrehookResult(
                modified_payload=PromptPrehookPayload(prompt_id=payload.prompt_id, args=masked),
                metadata={"telveguard": {"masked": counts}},
            )
        return PromptPrehookResult(continue_processing=True)

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
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
                        details={"tool": payload.name, "entities": leaked},
                    ),
                )
        return ToolPreInvokeResult(continue_processing=True)

    async def tool_post_invoke(self, payload: ToolPostInvokePayload, context: PluginContext) -> ToolPostInvokeResult:
        if self._cfg.scan_tool_results_for_injection:
            if v := self._injection_violation(_collect_text(payload.result), f"'{payload.name}' araç çıktısı"):
                return ToolPostInvokeResult(continue_processing=False, violation=v)

        if self._cfg.mask_tool_results:
            masked, counts = self._mask(payload.result, context)
            if counts:
                return ToolPostInvokeResult(
                    modified_payload=ToolPostInvokePayload(name=payload.name, result=masked),
                    metadata={"telveguard": {"masked": counts, "tool": payload.name}},
                )
        return ToolPostInvokeResult(continue_processing=True)
