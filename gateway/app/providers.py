"""
Model adına göre sağlayıcı yönlendirmesi (politika dosyasındaki `providers` bölümü).

    providers:
      - name: Google Gemini
        match: ["gemini-"]                 # model adı önekleri
        type: openai                       # openai | azure (chat, responses, embeddings) | anthropic
        url: https://generativelanguage.googleapis.com/v1beta/openai
        key_env: GEMINI_API_KEY            # anahtar ortam değişkeninden okunur, YAML'a yazılmaz
        destination: external              # internal | external (KVKK md. 9)
        country: ABD                       # VERBİS / KVKK raporunda aktarım ülkesi (opsiyonel)

Eşleşen sağlayıcının hedefi, politikadaki `destinations` önekinden önce gelir: veri gerçekte
nereye gidiyorsa karar ona göre verilir. Hiçbir sağlayıcı eşleşmezse eski yol kullanılır
(UPSTREAM_* ortam değişkenleri + `destinations`); `providers` yoksa davranış değişmez.

Biçim çevirisi yoktur: openai / azure tipleri chat + responses, anthropic tipi messages kabul
eder. Aynı önek için farklı tipte iki sağlayıcı tanımlanabilir; isteğin biçimine uyan seçilir.

Azure OpenAI:
  * api_version yoksa v1 API:  {url}/openai/v1/chat/completions   (model gövdede)
  * api_version varsa klasik:  {url}/openai/deployments/{deployment}/chat/completions?api-version=...
    deployment adı `deployments` eşlemesinden, yoksa model adının kendisi.
  Anahtar `api-key` başlığıyla gider.
"""
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

log = logging.getLogger("telveguard.providers")

TYPES = {"openai": {"chat", "responses", "embeddings"}, "azure": {"chat", "responses", "embeddings"},
         "anthropic": {"messages"}}
DESTINATIONS = {"internal", "external"}
ANTHROPIC_VERSION = "2023-06-01"
# Politika dosyası yalnızca *_KEY adlı değişkenleri isteyebilir: yanlış / kötü niyetli bir
# politika TELVEGUARD_ADMIN_TOKEN ya da CLICKHOUSE_PASSWORD'ü bir dış adrese gönderemesin.
KEY_ENV_RX = re.compile(r"^[A-Z][A-Z0-9_]*_KEY$")

# İstek biçimi -> sağlayıcı tipine göre yol
_PATHS = {
    "openai": {"chat": "/chat/completions", "responses": "/responses", "embeddings": "/embeddings"},
    "anthropic": {"messages": "/v1/messages", "count_tokens": "/v1/messages/count_tokens"},
}


@dataclass(frozen=True)
class Provider:
    name: str
    match: Tuple[str, ...]
    type: str
    url: str
    destination: str
    key_env: str = ""
    country: str = ""
    api_version: str = ""
    deployments: Mapping[str, str] = field(default_factory=dict)

    def matches(self, model: str) -> bool:
        return any(model.startswith(p) for p in self.match)

    def supports(self, kind: str) -> bool:
        return (kind if kind != "count_tokens" else "messages") in TYPES[self.type]

    def _key(self) -> str:
        return os.getenv(self.key_env, "") if self.key_env else ""

    def endpoint(self, kind: str, model: str, headers: Mapping[str, str]) -> Tuple[str, Dict[str, str]]:
        """kind: chat | responses | messages | count_tokens -> (url, başlıklar)"""
        base, key = self.url.rstrip("/"), self._key()
        if self.type == "anthropic":
            h = {"content-type": "application/json",
                 "anthropic-version": headers.get("anthropic-version", ANTHROPIC_VERSION)}
            if headers.get("anthropic-beta"):
                h["anthropic-beta"] = headers["anthropic-beta"]
            if key:
                h["x-api-key"] = key
            return base + _PATHS["anthropic"][kind], h
        h = {"Content-Type": "application/json"}
        if self.type == "openai":
            if key:
                h["Authorization"] = f"Bearer {key}"
            return base + _PATHS["openai"][kind], h
        # azure
        if key:
            h["api-key"] = key
        if not self.api_version:
            return f"{base}/openai/v1{_PATHS['openai'][kind]}", h
        if kind == "responses":
            return f"{base}/openai/responses?api-version={self.api_version}", h
        deployment = self.deployments.get(model, model)
        op = "embeddings" if kind == "embeddings" else "chat/completions"
        return f"{base}/openai/deployments/{deployment}/{op}?api-version={self.api_version}", h


class ProviderError(ValueError):
    pass


def _parse(i: int, raw: Any) -> Provider:
    if not isinstance(raw, dict):
        raise ProviderError(f"providers[{i}]: bir nesne olmalı")
    name = str(raw.get("name") or f"providers[{i}]")
    where = f"Sağlayıcı '{name}'"
    match = raw.get("match")
    if isinstance(match, str):
        match = [match]
    if not match or not all(isinstance(m, str) and m for m in match):
        raise ProviderError(f"{where}: match boş olmayan bir önek listesi olmalı")
    typ = raw.get("type", "openai")
    if typ not in TYPES:
        raise ProviderError(f"{where}: type şunlardan biri olmalı: {', '.join(TYPES)}")
    url = raw.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise ProviderError(f"{where}: url http(s):// ile başlamalı")
    dest = raw.get("destination", "external")
    if dest not in DESTINATIONS:
        raise ProviderError(f"{where}: destination internal ya da external olmalı")
    key_env = raw.get("key_env") or ""
    if key_env and not KEY_ENV_RX.match(key_env):
        raise ProviderError(f"{where}: key_env '_KEY' ile biten büyük harfli bir değişken adı olmalı "
                            "(ör. GEMINI_API_KEY)")
    if "key" in raw or "api_key" in raw:
        raise ProviderError(f"{where}: anahtar YAML'a yazılmaz; key_env ile ortam değişkeni adı verin")
    deployments = raw.get("deployments") or {}
    if typ != "azure" and (raw.get("api_version") or deployments):
        raise ProviderError(f"{where}: api_version / deployments yalnızca type: azure için")
    return Provider(name=name, match=tuple(match), type=typ, url=url, destination=dest, key_env=key_env,
                    country=str(raw.get("country") or ""), api_version=str(raw.get("api_version") or ""),
                    deployments={str(k): str(v) for k, v in deployments.items()})


class ProviderRegistry:
    def __init__(self, providers: List[Provider]):
        self.providers = providers

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]]) -> "ProviderRegistry":
        raw = (cfg or {}).get("providers") or []
        if not isinstance(raw, list):
            raise ProviderError("providers bir liste olmalı")
        providers = [_parse(i, p) for i, p in enumerate(raw)]
        for p in providers:
            if p.key_env and not os.getenv(p.key_env):
                log.warning("provider_key_missing provider=%s key_env=%s", p.name, p.key_env)
        return cls(providers)

    def resolve(self, model: str, kind: str) -> Tuple[Optional[Provider], Optional[str]]:
        """(sağlayıcı, hata). Eşleşme yoksa (None, None): eski UPSTREAM_* yolu. Önek eşleşip
        biçim uymuyorsa (None, açıklama): istek o biçimde bu sağlayıcıya gönderilemez."""
        matched = [p for p in self.providers if p.matches(model)]
        for p in matched:
            if p.supports(kind):
                return p, None
        if matched:
            kinds = sorted({k for p in matched for k in TYPES[p.type]})
            return None, (f"'{model}' modeli ({matched[0].name}) yalnızca şu API biçimleriyle kullanılabilir: "
                          f"{', '.join(kinds)}")
        return None, None

    def first(self, model: str) -> Optional[Provider]:
        return next((p for p in self.providers if p.matches(model)), None)

    def provider_name(self, model: str) -> Optional[str]:
        return next((p.name for p in self.providers if p.matches(model)), None)

    def countries(self) -> Dict[str, str]:
        return {p.name: p.country for p in self.providers if p.country}

    def describe(self) -> List[Dict[str, Any]]:
        """Arayüz için (adres ve anahtar adı yok)."""
        return [{"name": p.name, "match": list(p.match), "type": p.type, "destination": p.destination}
                for p in self.providers]


def load(policy_path: str) -> ProviderRegistry:
    """Politika dosyasındaki `providers` bölümü (PolicyEngine bu bölümü okumaz)."""
    import yaml

    with open(policy_path, encoding="utf-8") as f:
        return ProviderRegistry.from_config(yaml.safe_load(f))
