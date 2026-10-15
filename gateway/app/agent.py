"""
Kod asistanı hook'ları (Cursor, Claude Code): `telve hook ...` bu uca sorar.

Neden ayrı bir uç? Cursor'da "OpenAI base URL" ayarı veriyi korumaz: istek önce Cursor'un
sunucularına (ABD) gider, son prompt orada kurulur, Telveguard'a ancak ondan sonra ulaşır.
Kontrol noktası makinenin kendisidir: Cursor ve Claude Code, prompt gönderilmeden, dosya
okunmadan, komut çalışmadan önce yerel bir hook çalıştırır; hook metni bu uca gönderir,
karar burada (merkezi politikayla) verilir, denetim kaydı buradan yazılır.

Hook'lar çoğu yerde metni DEĞİŞTİREMEZ, yalnızca durdurabilir. Politika "maskele" diyorsa:
  * Claude Code Telveguard üzerinden gidiyorsa (routed) ve içerik modele gidiyorsa: geçir,
    gateway yolda maskeler
  * araç çıktısı (tool_output): maskeli metin döner, hook modelin gördüğünü değiştirir
  * diğerleri (Cursor prompt'u, dosya okuma, komut): durdur; maskesiz göndermektense
    kullanıcıya neden durdurulduğunu söylemek daha güvenlidir
Metin denetim kaydına yazılmaz (yalnızca özeti ve veri türleri), proxy'deki gibi.
"""
import re
from typing import Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field, field_validator

from telveguard_core.policy import Decision

CLIENTS = {"cursor": "Cursor", "claude-code": "Claude Code"}
EVENTS = {"prompt": "prompt", "file": "dosya", "shell": "komut",
          "tool_input": "araç çağrısı", "tool_output": "araç çıktısı"}
# Modele giden içerik: Claude Code Telveguard'dan geçiyorsa gateway bunları yolda maskeler.
# Komut ve araç argümanları ise modelden değil makineden dış sisteme gider; routed fark etmez.
TO_MODEL = {"prompt", "file", "tool_output"}
MAX_TEXT = 2_000_000


class AgentCheck(BaseModel):
    client: Literal["cursor", "claude-code"]
    event: Literal["prompt", "file", "shell", "tool_input", "tool_output"]
    text: str = Field(max_length=MAX_TEXT)
    model: str = Field("", max_length=200)
    # Claude Code ANTHROPIC_BASE_URL ile Telveguard'dan geçiyor: maskeleme yolda yapılır
    routed: bool = False
    agent_version: str = ""

    @field_validator("agent_version")
    @classmethod
    def _version(cls, v: str) -> str:
        if v and not re.fullmatch(r"[0-9a-z.+-]{1,30}", v):
            raise ValueError("sürüm biçimi geçersiz")
        return v


def destination(req: AgentCheck) -> Optional[str]:
    """Cursor'da veri, model ne olursa olsun önce Cursor'un sunucularına gider: yurt dışı.
    Claude Code'da model adından çıkarılır (None: gateway'in olağan kuralı)."""
    return "external" if req.client == "cursor" else None


def resolve(decision: Decision, req: AgentCheck) -> Tuple[str, str]:
    """Politika kararı -> hook'un uygulayacağı karar (allow | warn | mask | block) ve
    denetim kaydındaki politika aksiyonu."""
    if decision.action == "block":
        return "block", "block"
    if decision.action == "mask":
        if req.routed and req.event in TO_MODEL:
            return "allow", "mask"        # gateway yolda maskeleyecek
        if req.event == "tool_output":
            return "mask", "mask"
        return "block", "block"           # hook maskeleyemez: maskesiz gitmesin
    if decision.action == "alert":
        return "warn", "alert"
    return "allow", "allow"


def message(action: str, decision: Decision, req: AgentCheck, entities: Dict[str, int]) -> str:
    if action == "allow":
        return ""
    found = ", ".join(sorted(entities)) or "riskli içerik"
    what = EVENTS[req.event]
    if action == "mask":
        return f"Telveguard: {what} içindeki {found} maskelendi; model yer tutucuları görüyor."
    if action == "warn":
        return f"Telveguard uyarısı: {decision.reason or found} (izin verildi, kayda geçti)."
    reason = decision.reason or f"{found} içeriyor"
    if decision.action == "mask" and req.event in ("shell", "tool_input"):
        return f"Telveguard: {what} {found} içeriyor; komutlar ve araç çağrıları maskelenemediği için durduruldu."
    if decision.action == "mask":   # politika maskele dedi ama bu yolda maskelenemez
        return (f"Telveguard: {what} {found} içeriyor ve {CLIENTS[req.client]} bu veriyi maskeleyemiyor; "
                "gönderilmedi. Veriyi çıkarın ya da yer tutucuyla değiştirin (ör. [TCKN]).")
    return f"Telveguard: {what} durduruldu: {reason}"


def should_audit(req: AgentCheck, action: str, entities: Dict[str, int], decision: Decision,
                 injection_score: float) -> bool:
    """Her prompt kayda geçer (kullanım görünürlüğü). Dosya okuma, komut ve araç olayları
    yalnızca bir şey bulunduysa: Cursor her Tab tamamlamasında dosya okur, kayıt şişmesin.
    Telveguard'dan geçen Claude Code'un geçirilen içeriğini gateway zaten kaydeder: iki kez sayılmasın."""
    if req.routed and req.event in TO_MODEL and action == "allow":
        return False
    return (req.event == "prompt" or action != "allow" or bool(entities)
            or bool(decision.monitored_rules) or injection_score >= 0.5)


def audit_rules(decision: Decision, req: AgentCheck) -> List[str]:
    return decision.rules + [f"ajan:{req.client}:{req.event}"]
