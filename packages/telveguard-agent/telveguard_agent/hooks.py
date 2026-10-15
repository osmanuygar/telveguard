"""
Cursor ve Claude Code hook protokolleri: stdin'den olay JSON'u, stdout'a karar JSON'u.

Her olay gateway'deki /v1/agent/check'e sorulur (merkezi politika + denetim kaydı).
Gateway'e ulaşılamazsa:
  * fail_closed: durdur (kurumsal yapılandırmada önerilen)
  * değilse yerel tarama (telveguard-core): kişisel veri / sır / injection bulunursa yine
    durdurulur, temiz içerik geçer. Kurumsal sözlük yerelde yoktur.
Hook'un kendisi hata verirse Cursor'da izin hook'ları (dosya, komut, MCP) durur, prompt geçer;
Claude Code'da işlem devam eder. Bu yüzden her yol açıkça bir karar yazar.

Protokoller:
  Cursor  : https://cursor.com/docs/agent/hooks
  Claude  : https://code.claude.com/docs/en/hooks
"""
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .client import AuthRequired, GatewayError, check
from .config import Config, cache_dir

CURSOR_EVENTS = ["beforeSubmitPrompt", "beforeReadFile", "beforeTabFileRead",
                 "beforeShellExecution", "beforeMCPExecution"]
# Claude Code: araç girdisi (komut, MCP / web argümanları) çalışmadan önce, çıktısı modele
# gitmeden önce. Read / Grep çıktısı dosya içeriğidir: maskelenebilir, durdurmaya gerek yok.
CLAUDE_PRE_MATCHER = "Bash|WebFetch|WebSearch|mcp__.*"
CLAUDE_POST_MATCHER = "Read|Grep|Bash|WebFetch|mcp__.*"
BLOCK_NOTICE = "[Telveguard: bu içerik politika gereği modele gönderilmedi]"
CACHE_TTL = 300
CACHE_MAX = 2000


def log(msg: str) -> None:
    """stderr: Cursor'da "Hooks" çıktı kanalında, Claude Code'da --debug'da görünür."""
    print(f"telve: {msg}", file=sys.stderr)


# ---------------- karar ----------------

_local_engine = None


def _local(event: str, text: str) -> Dict[str, Any]:
    """Gateway yokken telveguard-core ile yerel tarama (politika yok: bulunan her şey riskli)."""
    global _local_engine
    from telveguard_core import InjectionDetector, TrPiiEngine
    if _local_engine is None:
        _local_engine = (TrPiiEngine(), InjectionDetector())
    pii, inj = _local_engine
    findings = pii.analyze(text)
    entities: Dict[str, int] = {}
    for f in findings:
        entities[f.entity] = entities.get(f.entity, 0) + 1
    injected = event in ("prompt", "file", "tool_output") and inj.scan(text).score >= 0.85
    if not entities and not injected:
        return {"action": "allow", "message": "", "entities": {}, "masked_text": None}
    found = ", ".join(sorted(entities)) or "prompt injection"
    if event == "tool_output" and entities and not injected:
        return {"action": "mask", "entities": entities, "masked_text": pii.mask(text).text,
                "message": f"Telveguard (çevrimdışı): araç çıktısındaki {found} maskelendi."}
    return {"action": "block", "entities": entities,
            "masked_text": pii.mask(text).text if event == "tool_output" else None,
            "message": f"Telveguard'a ulaşılamadı; içerik {found} içerdiği için yerel taramayla durduruldu."}


def _cache_key(client: str, event: str, text: str) -> str:
    return hashlib.sha256(f"{client}\0{event}\0{text}".encode("utf-8", "surrogatepass")).hexdigest()


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads((cache_dir() / "verdicts.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    hit = data.get(key)
    return {"action": "allow", "message": "", "masked_text": None} if hit and hit > time.time() else None


def _cache_put(key: str) -> None:
    path = cache_dir() / "verdicts.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    now = time.time()
    data = {k: v for k, v in data.items() if v > now}
    if len(data) >= CACHE_MAX:
        data = dict(sorted(data.items(), key=lambda kv: kv[1])[-CACHE_MAX // 2:])
    data[key] = now + CACHE_TTL
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def decide(cfg: Config, client: str, event: str, text: str, model: str = "", routed: bool = False,
           user_hint: str = "") -> Dict[str, Any]:
    if not text.strip():
        return {"action": "allow", "message": "", "masked_text": None}
    # Temiz dosya içeriği kısa süre önbellekte: Cursor Tab aynı dosyayı tekrar tekrar okur.
    # Yalnızca "izin" önbelleğe girer; durdurulan içerik her seferinde yeniden sorulur.
    cacheable = event == "file"
    key = _cache_key(client, event, text) if cacheable else ""
    if cacheable and (hit := _cache_get(key)):
        return hit
    try:
        result = check(cfg, client, event, text, model, routed, user_hint)
    except (GatewayError, AuthRequired) as e:
        log(str(e))
        if cfg.fail_closed:
            return {"action": "block", "masked_text": None,
                    "message": f"Telveguard'a ulaşılamadı ({e}); kurum politikası gereği durduruldu."}
        try:
            return _local(event, text)
        except ImportError:
            return {"action": "allow", "message": "", "masked_text": None}
    if cacheable and result["action"] == "allow":
        _cache_put(key)
    return result


def read_text_file(path: str, limit: int) -> Optional[str]:
    """Metin dosyasının (en fazla limit bayt) içeriği; ikili dosya / okunamayan dosya için None."""
    try:
        with open(path, "rb") as f:
            raw = f.read(limit)
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None   # ikili (görsel / PDF: gateway üzerinden gidiyorsa orada OCR'la taranır)
    return raw.decode("utf-8", errors="replace")


# ---------------- Cursor ----------------

def cursor(cfg: Config, data: Dict[str, Any]) -> Dict[str, Any]:
    event = data.get("hook_event_name", "")
    model = data.get("model") or ""
    limit = int(cfg.max_file_bytes)
    # Cursor oturumundaki e-posta: yalnızca giriş yapılmamışsa (header modu) kimlik beyanı olur
    who = data.get("user_email") if isinstance(data.get("user_email"), str) else ""

    def decide_(kind: str, text: str) -> Dict[str, Any]:
        return decide(cfg, "cursor", kind, text, model, user_hint=who)

    if event == "beforeSubmitPrompt":
        texts = [("prompt", data.get("prompt") or "")]
        for att in data.get("attachments") or []:
            if isinstance(att, dict) and att.get("file_path"):
                content = read_text_file(att["file_path"], limit)
                if content:
                    texts.append(("file", content))
        notes = []
        for kind, text in texts:
            r = decide_(kind, text)
            if r["action"] == "block":
                return {"continue": False, "user_message": r["message"]}
            if r["message"]:
                notes.append(r["message"])
        return {"continue": True, **({"user_message": "\n".join(notes)} if notes else {})}

    if event in ("beforeReadFile", "beforeTabFileRead"):
        if event == "beforeTabFileRead" and not cfg.tab_files:
            return {"permission": "allow"}
        content = data.get("content")
        if not isinstance(content, str):
            content = read_text_file(data.get("file_path", ""), limit) or ""
        r = decide_("file", content[:limit])
        out = {"permission": "deny" if r["action"] == "block" else "allow"}
        if r["message"] and event == "beforeReadFile":
            out["user_message"] = r["message"]
        return out

    if event in ("beforeShellExecution", "beforeMCPExecution"):
        if event == "beforeShellExecution":
            kind, text = "shell", data.get("command") or ""
        else:
            kind = "tool_input"
            text = json.dumps({"tool": data.get("tool_name"), "input": data.get("tool_input")}, ensure_ascii=False)
        r = decide_(kind, text)
        if r["action"] == "block":
            return {"permission": "deny", "user_message": r["message"], "agent_message": r["message"]}
        return {"permission": "allow", **({"user_message": r["message"]} if r["message"] else {})}

    return {}


# ---------------- Claude Code ----------------

def _replace_long_strings(value: Any, notice: str) -> Any:
    """Çıktının biçimini koruyarak içerik taşıyan (uzun) metinleri değiştirir. Claude Code
    yerleşik araçlarda biçime uymayan updatedToolOutput'u yok sayar: "type" gibi kısa
    alanlar aynen kalmalı."""
    if isinstance(value, str):
        return notice if len(value) >= 80 or "\n" in value else value
    if isinstance(value, list):
        return [_replace_long_strings(v, notice) for v in value]
    if isinstance(value, dict):
        return {k: _replace_long_strings(v, notice) for k, v in value.items()}
    return value


def claude(cfg: Config, data: Dict[str, Any], routed: bool = False) -> Dict[str, Any]:
    event = data.get("hook_event_name", "")

    if event == "UserPromptSubmit":
        r = decide(cfg, "claude-code", "prompt", data.get("prompt") or "", routed=routed)
        if r["action"] == "block":
            # suppressOriginalPrompt: engellenen prompt'taki veri ekranda / geçmişte kalmasın
            return {"decision": "block", "reason": r["message"],
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}
        return {"systemMessage": r["message"]} if r["message"] else {}

    if event == "PreToolUse":
        tool, tool_input = data.get("tool_name", ""), data.get("tool_input") or {}
        if tool == "Bash":
            kind, text = "shell", str(tool_input.get("command") or "")
        else:
            kind, text = "tool_input", json.dumps({"tool": tool, "input": tool_input}, ensure_ascii=False)
        r = decide(cfg, "claude-code", kind, text, routed=routed)
        if r["action"] == "block":
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                           "permissionDecisionReason": r["message"]}}
        return {"systemMessage": r["message"]} if r["message"] else {}

    if event == "PostToolUse":
        response = data.get("tool_response")
        if response is None:
            return {}
        text = response if isinstance(response, str) else json.dumps(response, ensure_ascii=False)
        r = decide(cfg, "claude-code", "tool_output", text, routed=routed)
        if r["action"] not in ("mask", "block"):
            return {"systemMessage": r["message"]} if r["message"] else {}
        masked: Any = r.get("masked_text") or text
        if not isinstance(response, str):
            try:
                masked = json.loads(masked)
            except ValueError:   # maskeleme JSON'u bozduysa: içeriği hiç gösterme
                masked, r = response, {**r, "action": "block"}
        if r["action"] == "block":
            masked = _replace_long_strings(masked, BLOCK_NOTICE)
        return {"systemMessage": r["message"],
                "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": masked,
                                       "additionalContext": r["message"]}}

    return {}


def run(adapter: Callable[[Dict[str, Any]], Dict[str, Any]]) -> int:
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace") or "{}")
    except ValueError:
        log("stdin geçerli JSON değil")
        data = {}
    out = adapter(data if isinstance(data, dict) else {})
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    return 0
