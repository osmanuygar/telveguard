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
from typing import Dict, List, Optional, Sequence, Tuple

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
        return self.assign_many(scope, [(entity, value)])[0]

    def assign_many(self, scope: str, items: Sequence[Tuple[str, str]]) -> List[str]:
        """Bir araç çıktısındaki tüm değerler toplu: 1 gidiş-dönüş (hepsi biliniyorsa) ya da 3
        (yeni değer varsa; aynı anda başka worker da atadıysa +1). Değer başına sıralı istek yok."""
        if not items:
            return []
        v_key, r_key, n_key = self._keys(scope)
        macs = [self._mac("value", e, canonical_value(e, v)) for e, v in items]
        new: Dict[str, Tuple[str, str]] = {}
        known: Dict[str, bytes] = {}
        uniq = list(dict.fromkeys(macs))
        pipe = self._r.pipeline(transaction=False)
        pipe.hmget(r_key, uniq)
        for k in (v_key, r_key, n_key):
            pipe.expire(k, self.ttl)
        for mac, ph in zip(uniq, pipe.execute()[0]):
            if ph is not None:
                known[mac] = ph
        for (e, v), mac in zip(items, macs):
            if mac not in known and mac not in new:
                new[mac] = (e, v)
        if new:
            pipe = self._r.pipeline(transaction=False)
            for e, _ in new.values():
                pipe.hincrby(n_key, e, 1)
            numbers = pipe.execute()
            candidates = {mac: f"[{e}_{n}]" for (mac, (e, _)), n in zip(new.items(), numbers)}
            pipe = self._r.pipeline(transaction=False)
            for mac, (_, v) in new.items():
                # Önce değer, sonra ters eşleme: ters eşlemeyi gören worker değeri de bulur
                pipe.hset(v_key, candidates[mac], self._seal(scope, candidates[mac], v))
                pipe.hsetnx(r_key, mac, candidates[mac])
            for k in (v_key, r_key, n_key):
                pipe.expire(k, self.ttl)
            won = pipe.execute()[1:2 * len(new):2]
            lost = [mac for mac, ok in zip(new, won) if not ok]
            for mac, ok in zip(new, won):
                if ok:
                    known[mac] = candidates[mac].encode("utf-8")
            if lost:   # başka worker aynı anda atadı: onunkini kullan (bizim numara boşa gider)
                pipe = self._r.pipeline(transaction=False)
                for mac in lost:
                    pipe.hdel(v_key, candidates[mac])
                pipe.hmget(r_key, lost)
                for mac, ph in zip(lost, pipe.execute()[-1]):
                    known[mac] = ph
        return [known[m].decode("utf-8") for m in macs]

    def lookup(self, scope: str, placeholder: str) -> Optional[str]:
        return self.lookup_many(scope, [placeholder])[0]

    def lookup_many(self, scope: str, placeholders: Sequence[str]) -> List[Optional[str]]:
        """Tek gidiş-dönüş. Bulunamayan ya da açılamayan kayıt None."""
        if not placeholders:
            return []
        out: List[Optional[str]] = []
        for ph, blob in zip(placeholders, self._r.hmget(self._keys(scope)[0], list(placeholders))):
            try:
                out.append(None if blob is None else self._open(scope, ph, blob))
            except Exception:   # bozuk / başka anahtarla yazılmış kayıt: bulunamadı say
                out.append(None)
        return out
