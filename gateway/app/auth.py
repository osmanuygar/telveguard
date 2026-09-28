"""
İstemci kimliği: kim istek atıyor, hangi ekiplerde?

AUTH_MODE=jwt (üretim): OIDC sağlayıcısının (Keycloak, Entra ID...) imzaladığı JWT.
    Uygulama token'ı OpenAI SDK'sında api_key olarak verir; SDK zaten
    "Authorization: Bearer <token>" gönderir, kod değişikliği gerekmez.
    x-telveguard-* header'ları bu modda YOK SAYILIR (sahtecilik yapılamaz).
AUTH_MODE=header (geliştirme): x-telveguard-user / x-telveguard-team header'ları; doğrulama yok.

Güvenlik kararları:
  * Yalnızca asimetrik algoritmalar (RS/PS/ES). "none" ve HS* reddedilir: HS256 kabul
    edilseydi saldırgan JWKS'teki public key'i HMAC sırrı gibi kullanıp token üretebilirdi.
  * iss, aud ve exp zorunlu; birkaç saniyelik saat kayması toleransı var.
  * İmza anahtarları (JWKS) asenkron çekilip önbelleğe alınır; bilinmeyen "kid" gelince
    (anahtar rotasyonu) yeniden çekilir, ama sahte kid'lerle IdP'yi yormamak için seyrekçe.
  * Kullanıcının TÜM ekipleri politikaya verilir: "stajyer" + "analitik" grubundaki biri
    stajyer kısıtından, grup sırasına güvenerek kaçamaz.
"""
import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
import jwt

log = logging.getLogger("telveguard.auth")

ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
MODES = ("header", "jwt")


@dataclass
class Identity:
    user: str
    teams: List[str] = field(default_factory=list)  # sıralı; ilki denetimde birincil ekip
    source: str = "header"

    @property
    def team(self) -> str:
        return self.teams[0] if self.teams else "default"


class AuthError(Exception):
    """reason: metrik/denetim için sınırlı küme; message: istemciye gösterilen metin."""

    def __init__(self, reason: str, message: str, status: int = 401):
        super().__init__(message)
        self.reason, self.message, self.status = reason, message, status


def _claim(claims: Dict[str, Any], path: str) -> Any:
    """Noktalı yol desteği: Keycloak rolleri için "realm_access.roles"."""
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


class Authenticator:
    def __init__(self, mode: str = "header", http: Optional[httpx.AsyncClient] = None, *,
                 issuer: str = "", audience: str = "", jwks_url: str = "",
                 user_claim: str = "preferred_username", team_claim: str = "groups",
                 team_prefix: str = "", leeway: int = 30, jwks_ttl: int = 300,
                 jwks_min_refresh: int = 30):
        if mode not in MODES:
            raise ValueError(f"AUTH_MODE '{mode}' geçersiz ({' | '.join(MODES)})")
        if mode == "jwt" and not (issuer and audience):
            raise ValueError("AUTH_MODE=jwt için OIDC_ISSUER ve OIDC_AUDIENCE zorunlu")
        self.mode, self.http = mode, http
        self.issuer, self.audience, self.jwks_url = issuer.rstrip("/"), audience, jwks_url
        self.user_claim, self.team_claim, self.team_prefix = user_claim, team_claim, team_prefix
        self.leeway, self.jwks_ttl, self.jwks_min_refresh = leeway, jwks_ttl, jwks_min_refresh
        self._keys: Dict[str, jwt.PyJWK] = {}
        self._fetched_at = 0.0      # son BAŞARILI çekim (TTL için)
        self._last_attempt = -1e9   # son deneme (başarısız olsa da): IdP'yi yormamak için
        self._lock = asyncio.Lock()
        if mode == "header":
            log.warning("AUTH_MODE=header: istemci kimliği DOĞRULANMIYOR (yalnızca geliştirme için)")

    @classmethod
    def from_env(cls, http: httpx.AsyncClient) -> "Authenticator":
        e = os.getenv
        return cls(e("AUTH_MODE", "header"), http,
                   issuer=e("OIDC_ISSUER", ""), audience=e("OIDC_AUDIENCE", ""),
                   jwks_url=e("OIDC_JWKS_URL", ""),
                   user_claim=e("OIDC_USER_CLAIM", "preferred_username"),
                   team_claim=e("OIDC_TEAM_CLAIM", "groups"), team_prefix=e("OIDC_TEAM_PREFIX", ""))

    # ---------------- kimlik ----------------

    async def authenticate(self, headers) -> Identity:
        if self.mode == "header":
            return Identity(headers.get("x-telveguard-user", "anonymous"),
                            [headers.get("x-telveguard-team", "default")], "header")
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer ") or not auth[7:].strip():
            raise AuthError("missing_token", "Kimlik doğrulama gerekli: Authorization: Bearer <JWT>")
        return await self._verify(auth[7:].strip())

    async def _verify(self, token: str) -> Identity:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            raise AuthError("malformed", "Geçersiz token biçimi")
        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise AuthError("bad_algorithm", f"İzin verilmeyen imza algoritması: {alg}")
        key = await self._key(header.get("kid"))
        try:
            claims = jwt.decode(token, key.key, algorithms=[alg], audience=self.audience,
                                issuer=self.issuer, leeway=self.leeway,
                                options={"require": ["exp", "iss", "aud"]})
        except jwt.ExpiredSignatureError:
            raise AuthError("expired", "Token süresi dolmuş")
        except jwt.InvalidAudienceError:
            raise AuthError("bad_audience", "Token bu servis için verilmemiş (aud)")
        except jwt.InvalidIssuerError:
            raise AuthError("bad_issuer", "Token beklenen kimlik sağlayıcısından değil (iss)")
        except jwt.InvalidTokenError:
            raise AuthError("invalid", "Token doğrulanamadı")
        user = _claim(claims, self.user_claim) or claims.get("sub")
        if not isinstance(user, str) or not user:
            raise AuthError("no_user", f"Token'da kullanıcı yok ({self.user_claim} / sub)")
        return Identity(user, self._teams(_claim(claims, self.team_claim)), "jwt")

    def _teams(self, raw: Any) -> List[str]:
        values = raw if isinstance(raw, list) else [raw] if isinstance(raw, str) else []
        teams: List[str] = []
        for v in values:
            if not isinstance(v, str):
                continue
            v = v.lstrip("/")  # Keycloak tam grup yolu: "/telveguard-analitik"
            if self.team_prefix:
                if not v.startswith(self.team_prefix):
                    continue
                v = v[len(self.team_prefix):]
            if v and v not in teams:
                teams.append(v)
        return teams or ["default"]

    # ---------------- imza anahtarları (JWKS) ----------------

    async def _key(self, kid: Optional[str]) -> jwt.PyJWK:
        # Hiç anahtar yoksa saatten bağımsız bayattır: monotonic() makinenin açık kalma süresi,
        # yeni açılmış makinede (CI, yeni node) TTL'den küçük olabilir
        stale = not self._keys or time.monotonic() - self._fetched_at > self.jwks_ttl
        if stale or (kid not in self._keys and self._may_refresh()):
            await self._refresh()
        if kid is None and len(self._keys) == 1:  # tek anahtarlı IdP'ler kid koymayabilir
            return next(iter(self._keys.values()))
        if kid not in self._keys:
            raise AuthError("unknown_key", "Token'ı imzalayan anahtar tanınmıyor")
        return self._keys[kid]

    def _may_refresh(self) -> bool:
        return time.monotonic() - self._last_attempt > self.jwks_min_refresh

    async def _refresh(self) -> None:
        async with self._lock:
            if not self._may_refresh():
                # Az önce denendi (bu istek kilidi beklerken başka istek yenilemiş ya da
                # IdP düşük): anahtar varsa onlarla devam, yoksa IdP'yi tekrar yoklama
                if self._keys:
                    return
                raise AuthError("jwks_unavailable", "Kimlik sağlayıcısına ulaşılamadı", 503)
            self._last_attempt = time.monotonic()
            try:
                url = self.jwks_url or await self._discover()
                r = await self.http.get(url, timeout=10)
                r.raise_for_status()
                keys = {}
                for k in jwt.PyJWKSet.from_dict(r.json()).keys:
                    keys[k.key_id] = k
            except (httpx.HTTPError, ValueError, KeyError, jwt.PyJWKSetError) as e:
                log.error("jwks_fetch_failed error=%s", type(e).__name__)
                if not self._keys:
                    raise AuthError("jwks_unavailable", "Kimlik sağlayıcısına ulaşılamadı", 503)
                return  # eski anahtarlarla devam; bir sonraki denemeye kadar
            self._keys, self._fetched_at = keys, self._last_attempt

    async def _discover(self) -> str:
        r = await self.http.get(f"{self.issuer}/.well-known/openid-configuration", timeout=10)
        r.raise_for_status()
        return r.json()["jwks_uri"]
