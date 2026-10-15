"""
`telve install cursor|claude`: hook'ları araçların yapılandırmasına yazar.

Kapsam:
  user       : yalnızca bu kullanıcı (~/.cursor/hooks.json, ~/.claude/settings.json)
  project    : bu depo (.cursor/hooks.json, .claude/settings.json); depoyla paylaşılır
  enterprise : makinedeki herkes; kullanıcı kapatamaz (yönetici yetkisi / MDM)
               Cursor: /Library/Application Support/Cursor/hooks.json (Enterprise plan)
               Claude: .../ClaudeCode/managed-settings.d/telveguard.json
--print yazmak yerine içeriği basar: MDM (Jamf, Intune) paketine konmak için.

Mevcut dosyadaki başka hook'lara dokunulmaz; yalnızca önceki Telveguard girdileri değiştirilir.
GUI uygulamaları kabuğun PATH'ini görmez: komut mutlak yolla yazılır.
"""
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .hooks import CLAUDE_POST_MATCHER, CLAUDE_PRE_MATCHER, CURSOR_EVENTS

MARK = "telve"   # komutta "telve hook" geçen girdiler bizimdir


def telve_command() -> str:
    found = shutil.which("telve")
    if found:
        return str(Path(found).resolve())
    argv0 = Path(sys.argv[0])
    return str(argv0.resolve()) if argv0.name.startswith("telve") else "telve"


def _quote(path: str) -> str:
    return f'"{path}"' if " " in path else path


def _is_ours(cmd: Any) -> bool:
    return isinstance(cmd, str) and f"{MARK} hook" in cmd.replace('"', "").replace(".exe", "").replace(
        os.sep, " ").replace("/", " ")


def _system_dir(app: str) -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support") / app
    if os.name == "nt":
        root = os.environ.get("PROGRAMFILES" if app == "ClaudeCode" else "PROGRAMDATA",
                              r"C:\Program Files" if app == "ClaudeCode" else r"C:\ProgramData")
        return Path(root) / app
    return Path("/etc") / ("claude-code" if app == "ClaudeCode" else "cursor")


def cursor_path(scope: str) -> Path:
    if scope == "enterprise":
        return _system_dir("Cursor") / "hooks.json"
    if scope == "project":
        return Path.cwd() / ".cursor" / "hooks.json"
    return Path.home() / ".cursor" / "hooks.json"


def claude_path(scope: str) -> Path:
    if scope == "enterprise":
        return _system_dir("ClaudeCode") / "managed-settings.d" / "telveguard.json"
    if scope == "project":
        return Path.cwd() / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def _load(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} bir JSON nesnesi değil")
    return data


# ---------------- Cursor ----------------

def cursor_config(existing: Dict[str, Any], command: str, fail_closed: bool, remove: bool = False) -> Dict[str, Any]:
    data = dict(existing)
    data.setdefault("version", 1)
    hooks = {k: [h for h in v if not _is_ours(h.get("command"))] for k, v in (data.get("hooks") or {}).items()}
    if not remove:
        for event in CURSOR_EVENTS:
            entry: Dict[str, Any] = {"command": f"{_quote(command)} hook cursor", "timeout": 15}
            if fail_closed:
                entry["failClosed"] = True
            hooks.setdefault(event, []).append(entry)
    data["hooks"] = {k: v for k, v in hooks.items() if v}
    return data


# ---------------- Claude Code ----------------

def _strip(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for g in groups:
        kept = [h for h in g.get("hooks", []) if not _is_ours(h.get("command"))]
        if kept:
            out.append({**g, "hooks": kept})
    return out


def claude_config(existing: Dict[str, Any], command: str, gateway: str = "", route: bool = False,
                  fail_closed: bool = False, remove: bool = False) -> Dict[str, Any]:
    data = dict(existing)
    hooks = {k: _strip(v) for k, v in (data.get("hooks") or {}).items()}
    env = dict(data.get("env") or {})
    if env.pop("TELVEGUARD_ROUTED", None):   # önceki --route kurulumunun izleri
        for k in ("ANTHROPIC_BASE_URL", "CLAUDE_CODE_API_KEY_HELPER_TTL_MS"):
            env.pop(k, None)
        data.pop("apiKeyHelper", None)

    if not remove:
        cmd = f"{_quote(command)} hook claude" + (" --routed" if route else "")
        handler: Dict[str, Any] = {"type": "command", "command": cmd, "timeout": 15}
        if fail_closed:
            handler["onFailure"] = "block"
        hooks.setdefault("UserPromptSubmit", []).append({"hooks": [handler]})
        hooks.setdefault("PreToolUse", []).append({"matcher": CLAUDE_PRE_MATCHER, "hooks": [handler]})
        hooks.setdefault("PostToolUse", []).append({"matcher": CLAUDE_POST_MATCHER, "hooks": [handler]})
        if route:
            # Model trafiği de Telveguard'dan: maskeleme yolda, cevap geri açılır, kota / maliyet
            env.update(ANTHROPIC_BASE_URL=gateway, CLAUDE_CODE_API_KEY_HELPER_TTL_MS="300000",
                       TELVEGUARD_ROUTED="1")
            data["apiKeyHelper"] = f"{_quote(command)} token"
    data["hooks"] = {k: v for k, v in hooks.items() if v}
    if not data["hooks"]:
        data.pop("hooks")
    if env:
        data["env"] = env
    else:
        data.pop("env", None)
    return data


def write(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def installed(path: Path) -> Optional[bool]:
    """None: dosya yok; True / False: Telveguard hook'u var mı."""
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return None
    return "hook cursor" in text or "hook claude" in text
