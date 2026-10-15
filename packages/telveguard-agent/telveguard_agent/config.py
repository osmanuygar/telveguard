"""
Yapılandırma: kurumsal (MDM ile dağıtılan) > ortam değişkeni > kullanıcı.

Kurumsal dosya yönetici yetkisiyle yazılır, kullanıcı değiştiremez: gateway adresi ve
"Telveguard'a ulaşılamazsa durdur" (fail_closed) gibi güvenlik ayarları oradan gelir.
"""
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULTS: Dict[str, Any] = {
    "gateway": "",              # https://telveguard.sirket.local
    "fail_closed": False,       # gateway'e ulaşılamazsa: True = durdur, False = yerel tarama
    "timeout": 8,               # saniye
    "ca_file": "",              # kurum içi CA (PEM); boşsa sistem sertifikaları
    "user": "",                 # yalnızca AUTH_MODE=header (geliştirme / demo)
    "team": "",
    "tab_files": True,          # Cursor Tab'ın okuduğu dosyalar da taransın mı
    "max_file_bytes": 1_000_000,  # bundan büyük dosyanın yalnızca başı taranır
    "oidc": None,               # {"issuer", "client_id", "scope"}; boşsa gateway'den öğrenilir
}


def managed_path() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/Telveguard/agent.json")
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Telveguard" / "agent.json"
    return Path("/etc/telveguard/agent.json")


def user_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home())) / "Telveguard"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "telveguard"


def cache_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Telveguard" / "cache"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "telveguard"


def _read(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise ConfigError(f"{path} okunamadı: {e}")
    if not isinstance(data, dict):
        raise ConfigError(f"{path} bir JSON nesnesi olmalı")
    return data


class ConfigError(Exception):
    pass


@dataclass
class Config:
    values: Dict[str, Any]
    managed_keys: List[str] = field(default_factory=list)   # kullanıcının değiştiremedikleri
    sources: List[str] = field(default_factory=list)

    def __getattr__(self, name: str) -> Any:
        try:
            return self.__dict__["values"][name]
        except KeyError:
            raise AttributeError(name)

    @property
    def gateway_url(self) -> str:
        return str(self.values["gateway"]).rstrip("/")


def load() -> Config:
    values = dict(DEFAULTS)
    sources = []
    user_file = user_dir() / "agent.json"
    user = _read(user_file)
    if user:
        values.update(user)
        sources.append(str(user_file))
    if os.environ.get("TELVEGUARD_URL"):
        values["gateway"] = os.environ["TELVEGUARD_URL"]
        sources.append("TELVEGUARD_URL")
    managed = _read(managed_path())
    if managed:
        values.update(managed)
        sources.append(str(managed_path()))
    return Config(values, sorted(managed), sources)


def save_user(updates: Dict[str, Any]) -> Path:
    path = user_dir() / "agent.json"
    data = _read(path)
    data.update(updates)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def default_user() -> Optional[str]:
    return os.environ.get("USER") or os.environ.get("USERNAME")
