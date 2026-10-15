"""
Gateway ile konuşma (yalnızca standart kütüphane: hook her olayda yeniden başlar, hızlı açılmalı)
ve kimlik: OIDC cihaz akışı (RFC 8628) ile giriş, refresh token ile sessiz yenileme.

Token'lar kullanıcının yapılandırma dizininde, yalnızca kullanıcının okuyabileceği bir dosyada
durur (gcloud / kubectl gibi). Claude Code'un apiKeyHelper'ı `telve token`ı çağırır.
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from . import __version__
from .config import Config, default_user, user_dir


class GatewayError(Exception):
    """Gateway'e ulaşılamadı ya da beklenmeyen cevap (hook fail_closed'a göre davranır)."""


class AuthRequired(Exception):
    """Giriş yapılmamış ya da oturum yenilenemedi: `telve login`."""


def _ssl(cfg: Config) -> Optional[ssl.SSLContext]:
    return ssl.create_default_context(cafile=cfg.ca_file) if cfg.ca_file else None


def http_json(cfg: Config, method: str, url: str, body: Any = None, headers: Optional[Dict[str, str]] = None,
              form: bool = False) -> Tuple[int, Any]:
    data = None
    h = {"accept": "application/json", "user-agent": f"telve/{__version__}"}
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            h["content-type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            h["content-type"] = "application/json"
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout, context=_ssl(cfg)) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise GatewayError(f"{urllib.parse.urlsplit(url).netloc} adresine ulaşılamadı: "
                           f"{getattr(e, 'reason', e)}")
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        raise GatewayError(f"{url} JSON olmayan cevap döndü ({status})")


# ---------------- kimlik ----------------

def _cred_path():
    return user_dir() / "credentials.json"


def load_credentials() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(_cred_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None


def save_credentials(creds: Dict[str, Any]) -> None:
    path = _cred_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(creds, f)
    os.chmod(path, 0o600)


def clear_credentials() -> bool:
    try:
        _cred_path().unlink()
        return True
    except FileNotFoundError:
        return False


def gateway_info(cfg: Config) -> Dict[str, Any]:
    status, info = http_json(cfg, "GET", f"{cfg.gateway_url}/v1/agent/config")
    if status != 200 or not isinstance(info, dict):
        raise GatewayError(f"Gateway kurulum bilgisi alınamadı ({status}); sürümü 0.4 öncesi olabilir")
    return info


def _oidc_endpoints(cfg: Config, oidc: Dict[str, str]) -> Dict[str, Any]:
    status, meta = http_json(cfg, "GET", oidc["issuer"].rstrip("/") + "/.well-known/openid-configuration")
    if status != 200 or not isinstance(meta, dict):
        raise GatewayError(f"OIDC keşif belgesi alınamadı ({status})")
    return meta


def device_login(cfg: Config, oidc: Dict[str, str], announce) -> Dict[str, Any]:
    """RFC 8628: kullanıcı tarayıcıda kodu onaylar, bu süreç token gelene kadar bekler."""
    if not oidc.get("client_id"):
        raise GatewayError("OIDC istemci kimliği yok: gateway'de OIDC_AGENT_CLIENT_ID tanımlanmalı")
    meta = _oidc_endpoints(cfg, oidc)
    if not meta.get("device_authorization_endpoint"):
        raise GatewayError("Kimlik sağlayıcı cihaz akışını (device authorization grant) desteklemiyor")
    status, dev = http_json(cfg, "POST", meta["device_authorization_endpoint"], form=True,
                            body={"client_id": oidc["client_id"], "scope": oidc.get("scope") or "openid"})
    if status != 200:
        raise GatewayError(f"Cihaz kodu alınamadı ({status}): {dev}")
    announce(dev.get("verification_uri_complete") or dev["verification_uri"], dev["user_code"])
    interval = int(dev.get("interval", 5))
    deadline = time.time() + int(dev.get("expires_in", 600))
    while time.time() < deadline:
        time.sleep(interval)
        status, tok = http_json(cfg, "POST", meta["token_endpoint"], form=True, body={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dev["device_code"], "client_id": oidc["client_id"]})
        if status == 200:
            return _store(tok, meta["token_endpoint"], oidc["client_id"])
        err = (tok or {}).get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        raise AuthRequired({"access_denied": "Giriş reddedildi.",
                            "expired_token": "Kodun süresi doldu; yeniden deneyin."}.get(err, f"Giriş başarısız: {err}"))
    raise AuthRequired("Kodun süresi doldu; yeniden deneyin.")


def _store(tok: Dict[str, Any], token_endpoint: str, client_id: str, old: Optional[Dict] = None) -> Dict[str, Any]:
    creds = {"access_token": tok["access_token"],
             "refresh_token": tok.get("refresh_token") or (old or {}).get("refresh_token"),
             "expires_at": int(time.time()) + int(tok.get("expires_in", 300)),
             "token_endpoint": token_endpoint, "client_id": client_id}
    save_credentials(creds)
    return creds


def access_token(cfg: Config) -> str:
    """Geçerli access token; süresi bitmek üzereyse refresh token ile yeniler."""
    if os.environ.get("TELVEGUARD_TOKEN"):
        return os.environ["TELVEGUARD_TOKEN"]
    creds = load_credentials()
    if not creds:
        raise AuthRequired("Giriş yapılmamış: telve login")
    if creds.get("expires_at", 0) - 60 > time.time() or not creds.get("token_endpoint"):
        return creds["access_token"]   # statik token (telve login --token) süresizdir
    if not creds.get("refresh_token"):
        raise AuthRequired("Oturum süresi doldu: telve login")
    status, tok = http_json(cfg, "POST", creds["token_endpoint"], form=True, body={
        "grant_type": "refresh_token", "refresh_token": creds["refresh_token"], "client_id": creds["client_id"]})
    if status != 200:
        raise AuthRequired("Oturum yenilenemedi: telve login")
    return _store(tok, creds["token_endpoint"], creds["client_id"], creds)["access_token"]


def auth_headers(cfg: Config, user_hint: str = "") -> Dict[str, str]:
    """jwt modunda Bearer token: kişi token'dan gelir, doğrulanır. Giriş yoksa kullanıcı / ekip
    beyanı (header modu: geliştirme / demo; jwt modunda gateway bunu reddeder -> telve login).
    Beyan sırası: yapılandırma (MDM) > aracın bildirdiği (Cursor: user_email) > OS kullanıcısı."""
    try:
        return {"authorization": f"Bearer {access_token(cfg)}"}
    except AuthRequired:
        return {"x-telveguard-user": cfg.user or user_hint or default_user() or "unknown",
                "x-telveguard-team": cfg.team or "default"}


def check(cfg: Config, client: str, event: str, text: str, model: str = "", routed: bool = False,
          user_hint: str = "") -> Dict[str, Any]:
    if not cfg.gateway_url:
        raise GatewayError("Gateway adresi tanımlı değil: telve setup --gateway https://...")
    status, body = http_json(cfg, "POST", f"{cfg.gateway_url}/v1/agent/check", headers=auth_headers(cfg, user_hint), body={
        "client": client, "event": event, "text": text, "model": model or "", "routed": routed,
        "agent_version": __version__})
    if status == 401:
        raise AuthRequired("Gateway kimliği reddetti: telve login")
    if status != 200 or not isinstance(body, dict) or "action" not in body:
        msg = ((body or {}).get("error") or {}).get("message") if isinstance(body, dict) else None
        raise GatewayError(f"Gateway {status} döndü" + (f": {msg}" if msg else ""))
    return body
