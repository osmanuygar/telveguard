"""
Sır / kimlik bilgisi tanıyıcıları: prompt'a yapıştırılan API anahtarları, token'lar,
private key'ler ve parolalı bağlantı dizeleri. Kod yapıştıran geliştiricilerde en sık
görülen gerçek sızıntı türü budur.

Tüm varlıklar SECRET_ önekli; politikada `entity_in: ["SECRET_*"]` ile topluca seçilir.
Sağlayıcıya özgü desenler (sabit önek + uzunluk) yüksek skorlu; bağlamlı parola deseni
yanlış pozitife daha açık olduğu için düşük skorlu.
"""
import re
from typing import List

from .tr_recognizers import Recognizer

_I = re.IGNORECASE

# Parola "değeri" gibi görünen ama parola olmayanlar: anahtar kelimelerin kendisi, boş değerler
_NOT_PASSWORDS = {"password", "passwd", "pwd", "parola", "şifre", "sifre", "secret", "none", "null",
                  "true", "false", "undefined", "required", "optional", "string", "example"}
_CODE_REF = re.compile(
    r"^(?:\$|%\(|\{\{|<|os\.|self\.|this\.|process\.env|env\.|config\.|settings\.|getenv|environ)", _I)


def _looks_like_password(value: str) -> bool:
    """Kod ve yapılandırmada `password=password`, `${DB_PASSWORD}`, `os.getenv(...)`,
    `********`, `<şifreniz>` gibi kalıplar parola değildir. Zayıf ama gerçek parolalar
    (changeme123, Summer2026) yakalanmaya devam eder: yalnızca açıkça parola olmayanlar elenir."""
    v = value.strip("\"'`")
    if v.lower() in _NOT_PASSWORDS or _CODE_REF.match(v):
        return False
    if len(set(v)) == 1:                     # ******** / xxxxxx
        return False
    if re.fullmatch(r"[A-Za-z_]\w*(?:\.\w+)+", v) or "(" in v:   # nesne.alan / çağrı()
        return False
    if re.fullmatch(r"[A-Z]\w*\[.*\]", v):   # tip ifadesi: Optional[str], List[str]
        return False
    if re.fullmatch(r"\[[A-Z_]+_\d+\]", v):  # Telveguard'ın kendi yer tutucusu (maskeli metin tekrar taranırsa)
        return False
    return True

SECRET_RECOGNIZERS: List[Recognizer] = [
    Recognizer("SECRET_AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 1.0),
    Recognizer("SECRET_AWS_KEY", re.compile(
        r"aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", _I), 1.0, group=1),
    Recognizer("SECRET_GITHUB_TOKEN", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), 1.0),
    Recognizer("SECRET_ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), 1.0),
    # sk-ant- Anthropic'e ait; OpenAI deseni onu tekrar saymasın
    Recognizer("SECRET_OPENAI_KEY", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"), 1.0),
    Recognizer("SECRET_SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 1.0),
    Recognizer("SECRET_GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"), 1.0),
    Recognizer("SECRET_STRIPE_KEY", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"), 1.0),
    # END satırı kesilmişse (yarım yapıştırma) metnin sonuna kadar maskelenir
    Recognizer("SECRET_PRIVATE_KEY", re.compile(
        r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----|[\s\S]*)"), 1.0),
    Recognizer("SECRET_JWT", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 1.0),
    # Sadece parola içeren bağlantı dizeleri (kullanıcı:parola@host)
    Recognizer("SECRET_DB_URL", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)"
        r"://[^\s:/@]+:[^\s@/]+@[^\s\"'<>]+", _I), 1.0),
    # "password": "x" (JSON) için anahtar sonrası tırnak da olabilir
    Recognizer("SECRET_PASSWORD", re.compile(
        r"(?:password|passwd|pwd|parola|şifre|sifre)[\"']?\s*[=:]\s*[\"']?([^\s\"',;)]{6,})", _I), 0.8,
        _looks_like_password, group=1),
]
