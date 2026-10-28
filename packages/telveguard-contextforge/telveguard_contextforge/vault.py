# -*- coding: utf-8 -*-
"""
Araç çağrıları arasında kalıcı yer tutucu vault'u (Redis; SPDX-License-Identifier: Apache-2.0).

ContextForge'da her MCP tools/call ayrı bir HTTP isteğidir; eklentinin context.state'i çağrı
bitince ölür. Agent bir araçtan aldığı [TCKN_1]'i başka bir araca verdiğinde gerçek değer
bulunabilsin diye eşleme Redis'te, KULLANICI kapsamında tutulur:

  tv:cf:{kapsam}:v  yer tutucu -> şifreli değer (AES-GCM; ek veri: kapsam + yer tutucu)
  tv:cf:{kapsam}:r  HMAC(tür, normalleştirilmiş değer) -> yer tutucu   (Redis'te ham değer yok)
  tv:cf:{kapsam}:n  tür -> son numara (HINCRBY: worker'lar arasında çakışmasız numara)

kapsam = HMAC(anahtar, tenant + kullanıcı): kullanıcı adı / e-posta Redis anahtarında görünmez,
bir kullanıcının vault'u başkasınınkinden okunamaz. Her yazımda süre (TTL) yenilenir.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Optional

from telveguard_core.pii.engine import canonical_value

PREFIX = "tv:cf:"


class VaultError(RuntimeError):
    pass


class RedisVault:
    def __init__(self, client, key: bytes, ttl_seconds: int):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(key) < 32:
            raise VaultError("vault anahtarı en az 32 bayt olmalı")
        self._r = client
        self._enc_key = hmac.new(key, b"telveguard-vault-enc", hashlib.sha256).digest()
        self._mac_key = hmac.new(key, b"telveguard-vault-mac", hashlib.sha256).digest()
        self._aead = AESGCM(self._enc_key)
        self.ttl = ttl_seconds

    @classmethod
    def from_env(cls, url_env: str, key_env: str, ttl_seconds: int) -> Optional["RedisVault"]:
        """Redis adresi yoksa None (çağrı içi vault). Adres var ama anahtar yoksa hata: kişisel veri
        Redis'e şifresiz yazılmasın."""
        url = os.getenv(url_env, "")
        if not url:
            return None
        key = os.getenv(key_env, "")
        if len(key.encode("utf-8")) < 32:
            raise VaultError(f"{url_env} tanımlı ama {key_env} yok ya da 32 karakterden kısa")
        import redis

        client = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
        return cls(client, key.encode("utf-8"), ttl_seconds)

    def _mac(self, *parts: str) -> str:
        return hmac.new(self._mac_key, "\n".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def scope(self, tenant: Optional[str], user: str) -> str:
        return self._mac("scope", tenant or "", user)

    def _keys(self, scope: str):
        base = f"{PREFIX}{scope}:"
        return base + "v", base + "r", base + "n"

    def _seal(self, scope: str, placeholder: str, value: str) -> str:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, value.encode("utf-8"), f"{scope}\n{placeholder}".encode("utf-8"))
        return base64.b64encode(nonce + ct).decode("ascii")

    def _open(self, scope: str, placeholder: str, blob: bytes) -> str:
        raw = base64.b64decode(blob)
        pt = self._aead.decrypt(raw[:12], raw[12:], f"{scope}\n{placeholder}".encode("utf-8"))
        return pt.decode("utf-8")

    def assign(self, scope: str, entity: str, value: str) -> str:
        """Değerin bu kullanıcıdaki yer tutucusu; yoksa yeni numara alır."""
        v_key, r_key, n_key = self._keys(scope)
        rev = self._mac("value", entity, canonical_value(entity, value))
        existing = self._r.hget(r_key, rev)
        if existing is None:
            n = self._r.hincrby(n_key, entity, 1)
            candidate = f"[{entity}_{n}]"
            # Önce değer, sonra ters eşleme: ters eşlemeyi gören worker değeri de bulur
            self._r.hset(v_key, candidate, self._seal(scope, candidate, value))
            if self._r.hsetnx(r_key, rev, candidate):
                existing = candidate.encode("utf-8")
            else:   # başka worker aynı anda atadı: onunkini kullan (bizim numara boşa gider)
                self._r.hdel(v_key, candidate)
                existing = self._r.hget(r_key, rev)
        pipe = self._r.pipeline()
        for k in (v_key, r_key, n_key):
            pipe.expire(k, self.ttl)
        pipe.execute()
        return existing.decode("utf-8")

    def lookup(self, scope: str, placeholder: str) -> Optional[str]:
        blob = self._r.hget(self._keys(scope)[0], placeholder)
        if blob is None:
            return None
        try:
            return self._open(scope, placeholder, blob)
        except Exception:   # bozuk / başka anahtarla yazılmış kayıt: bulunamadı say
            return None
