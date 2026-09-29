"""
AI envanteri, EU AI Act risk sınıflandırması ve VERBİS taslağı.

ÖNEMLİ: Çıktılar TASLAKTIR, hukuki tavsiye değildir; hukuk biriminin onayı gerekir.

Risk sınıfını model ya da trafik değil KULLANIM AMACI belirler: aynı model müşteri sorularını
yanıtlarken "sınırlı", işe alımda aday elerken "yüksek" risklidir. Bu yüzden kurum AI
sistemlerini `inventory.yaml`'da beyan eder (ad, ekip, modeller, kullanım amacı); Telveguard
beyanı aşağıdaki kataloğa göre sınıflandırır ve denetim kayıtlarında görülüp hiçbir beyana
uymayan kullanımları "beyan edilmemiş" diye işaretler.

Kaynaklar (2026-09 itibarıyla):
  * Regulation (EU) 2024/1689 (AI Act): md. 4, 5, 26, 50; Ek III
  * Regulation (EU) 2026/1744 (Digital Omnibus on AI, yürürlük 27.07.2026): Ek III yüksek risk
    2.12.2027, Ek I 2.8.2028, md. 50 şeffaflık 2.8.2026, yeni yasaklar (md. 5(1)(ba),(bb)) 2.12.2026;
    md. 4 AI okuryazarlığı "personelin gelişimini destekleme" yükümlülüğüne yumuşatıldı
  * 6698 sayılı KVKK md. 9 (7499 sayılı Kanunla değişik, 1.6.2024): yeterlilik -> uygun güvenceler
    (standart sözleşme: imzadan sonra 5 iş günü içinde Kurul'a bildirim; BCR) -> istisnai haller
  * Veri Sorumluları Sicili Hakkında Yönetmelik (VERBİS başlıkları)
"""
import csv
import io
from datetime import date
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Optional

import yaml

from .xray import _csv_safe  # CSV formül enjeksiyonu koruması (KVKK raporuyla aynı)

DISCLAIMER = ("TASLAK - hukuki tavsiye değildir. Risk sınıfı beyan edilen kullanım amacına göre "
              "otomatik önerilmiştir; nihai değerlendirme hukuk / uyum biriminindir.")

AI_LITERACY = "Personelin AI okuryazarlığının geliştirilmesini destekleyin (md. 4)."
HIGH_RISK_DEPLOYER = [
    "Sağlayıcının kullanım talimatına uygun kullanın (md. 26/1).",
    "Yetkin ve yetkili kişilerle insan gözetimi sağlayın (md. 26/2).",
    "Girdi verisinin amaca uygun ve temsil edici olmasını sağlayın (md. 26/4).",
    "İşleyişi izleyin; ciddi olayları sağlayıcıya ve otoriteye bildirin (md. 26/5).",
    "Otomatik kayıtları en az 6 ay saklayın (md. 26/6) - Telveguard denetim kaydı bunu karşılar.",
    "Etkilenen kişileri, hakkında karar verilmesinde yüksek riskli AI kullanıldığı konusunda bilgilendirin (md. 26/11).",
]

# id -> (etiket, risk, dayanak, yürürlük, ek yükümlülükler)
# risk: prohibited | high | limited | minimal
USE_CASES: Dict[str, Dict[str, Any]] = {
    # ---- md. 5 yasak uygulamalar ----
    "manipulation": ("Bilinçaltı / manipülatif tekniklerle davranışı çarpıtma", "prohibited", "md. 5(1)(a)", "2025-02-02"),
    "exploiting_vulnerabilities": ("Yaş, engellilik, sosyoekonomik durum zaafının istismarı", "prohibited", "md. 5(1)(b)", "2025-02-02"),
    "intimate_imagery": ("Rızasız mahrem görüntü üretme / değiştirme", "prohibited", "md. 5(1)(ba) (Omnibus)", "2026-12-02"),
    "csam": ("Çocuk istismarı içeriği üretme / değiştirme", "prohibited", "md. 5(1)(bb) (Omnibus)", "2026-12-02"),
    "social_scoring": ("Sosyal puanlama", "prohibited", "md. 5(1)(c)", "2025-02-02"),
    "predictive_policing": ("Yalnızca profillemeye dayalı suç tahmini", "prohibited", "md. 5(1)(d)", "2025-02-02"),
    "facial_scraping": ("Hedefsiz yüz görüntüsü toplama (internet / kamera)", "prohibited", "md. 5(1)(e)", "2025-02-02"),
    "emotion_recognition_workplace": ("İşyerinde / eğitimde duygu tanıma (tıbbi / güvenlik hariç)", "prohibited", "md. 5(1)(f)", "2025-02-02"),
    "sensitive_biometric_categorisation": ("Irk, siyasi görüş, din, cinsel yönelim çıkaran biyometrik sınıflandırma", "prohibited", "md. 5(1)(g)", "2025-02-02"),
    "realtime_biometric_id_public": ("Kamuya açık alanda gerçek zamanlı uzaktan biyometrik tanıma (kolluk)", "prohibited", "md. 5(1)(h)", "2025-02-02"),
    # ---- Ek III yüksek risk ----
    "biometric_identification": ("Uzaktan biyometrik tanıma", "high", "Ek III 1(a)", "2027-12-02"),
    "biometric_categorisation": ("Hassas / korunan niteliklere göre biyometrik sınıflandırma", "high", "Ek III 1(b)", "2027-12-02"),
    "emotion_recognition": ("Duygu tanıma (işyeri / eğitim dışı)", "high", "Ek III 1(c)", "2027-12-02"),
    "critical_infrastructure": ("Kritik altyapı güvenlik bileşeni (dijital altyapı, trafik, su, gaz, ısı, elektrik)", "high", "Ek III 2", "2027-12-02"),
    "education_admission": ("Eğitime kabul / yerleştirme", "high", "Ek III 3(a)", "2027-12-02"),
    "education_assessment": ("Öğrenme çıktısı değerlendirme / seviye belirleme / sınav gözetimi", "high", "Ek III 3(b)-(d)", "2027-12-02"),
    "recruitment": ("İşe alım: ilan hedefleme, başvuru eleme, aday değerlendirme", "high", "Ek III 4(a)", "2027-12-02"),
    "worker_management": ("Terfi, fesih, görev dağılımı, performans izleme", "high", "Ek III 4(b)", "2027-12-02"),
    "public_benefits": ("Kamu yardımı / sağlık hizmeti uygunluk değerlendirmesi", "high", "Ek III 5(a)", "2027-12-02"),
    "credit_scoring": ("Kredi değerliliği / kredi skoru", "high", "Ek III 5(b)", "2027-12-02"),
    "insurance_pricing": ("Hayat / sağlık sigortası risk değerlendirme ve fiyatlama", "high", "Ek III 5(c)", "2027-12-02"),
    "emergency_dispatch": ("Acil çağrı sınıflandırma / acil servis yönlendirme", "high", "Ek III 5(d)", "2027-12-02"),
    "law_enforcement": ("Kolluk: mağduriyet / tekrar suç riski, delil güvenilirliği, profilleme", "high", "Ek III 6", "2027-12-02"),
    "migration_border": ("Göç, iltica, sınır kontrolü", "high", "Ek III 7", "2027-12-02"),
    "justice_elections": ("Yargıya destek / seçim ve oy davranışını etkileme", "high", "Ek III 8", "2027-12-02"),
    # ---- md. 50 şeffaflık (sınırlı risk) ----
    "chatbot_public": ("Kişilerle doğrudan etkileşen asistan / chatbot", "limited", "md. 50(1)", "2026-08-02"),
    "public_content_generation": ("Kamuoyuna yönelik üretilen metin / görsel / deepfake", "limited", "md. 50(2), 50(4)", "2026-08-02"),
    # ---- minimal risk (yalnızca md. 4) ----
    "internal_productivity": ("Kurum içi verimlilik (özet, taslak, çeviri, arama)", "minimal", "yalnızca md. 4", "2025-02-02"),
    "code_assistant": ("Yazılım geliştirme asistanı", "minimal", "yalnızca md. 4", "2025-02-02"),
    "data_analysis": ("Kurum içi veri analizi / raporlama", "minimal", "yalnızca md. 4", "2025-02-02"),
    "customer_support_internal": ("Müşteri temsilcisine taslak cevap (kişiyle doğrudan etkileşmez)", "minimal", "yalnızca md. 4", "2025-02-02"),
}
USE_CASES = {k: dict(zip(("label", "risk", "ref", "applies_from"), v)) for k, v in USE_CASES.items()}

RISK_LABELS = {"prohibited": "Yasak", "high": "Yüksek risk", "limited": "Sınırlı risk (şeffaflık)",
               "minimal": "Minimal risk", "unclassified": "Sınıflandırılmamış"}
RISK_ORDER = {"prohibited": 0, "unclassified": 1, "high": 2, "limited": 3, "minimal": 4}


def obligations(use_case: str) -> List[str]:
    uc = USE_CASES[use_case]
    risk = uc["risk"]
    if risk == "prohibited":
        return [f"Bu kullanım yasaktır ({uc['ref']}, {uc['applies_from']} itibarıyla). Sistemi durdurun."]
    out = [AI_LITERACY]
    if risk == "high":
        out += HIGH_RISK_DEPLOYER
        out.append(f"Yüksek risk yükümlülükleri {uc['applies_from']} tarihinden itibaren uygulanır "
                   "(Omnibus ile ertelendi); kamu kurumu, kredi ve sigorta uygulayıcıları için temel "
                   "haklar etki değerlendirmesi de gerekebilir (md. 27).")
    if use_case == "chatbot_public":
        out.append("Kişilere yapay zekâ ile etkileşimde oldukları bildirilmeli (md. 50/1).")
    if use_case == "public_content_generation":
        out.append("Üretilen içerik makine tarafından okunabilir biçimde işaretlenmeli ve deepfake / kamuoyunu "
                   "bilgilendiren üretilmiş metin açıkça belirtilmeli (md. 50/2, 50/4).")
    return out


# ---------------- envanter beyanları ----------------

REQUIRED = ("id", "name", "owner_team", "models", "use_case", "purpose")


def load_inventory(path: Optional[str]) -> Dict[str, Any]:
    """inventory.yaml: yoksa boş envanter (tüm kullanımlar 'beyan edilmemiş' görünür)."""
    if not path:
        return {"systems": []}
    try:
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {"systems": []}
    validate_inventory(cfg)
    return cfg


def validate_inventory(cfg: Dict[str, Any]) -> None:
    seen = set()
    for i, s in enumerate(cfg.get("systems") or []):
        missing = [k for k in REQUIRED if not s.get(k)]
        if missing:
            raise ValueError(f"inventory.systems[{i}]: eksik alan(lar): {', '.join(missing)}")
        if s["use_case"] not in USE_CASES:
            raise ValueError(f"inventory.systems[{i}] ({s['id']}): bilinmeyen use_case '{s['use_case']}'. "
                             f"Geçerli: {', '.join(sorted(USE_CASES))}")
        if s["id"] in seen:
            raise ValueError(f"inventory: '{s['id']}' iki kez tanımlı")
        seen.add(s["id"])


def _teams(system: Dict[str, Any]) -> set:
    t = system["owner_team"]
    return set(t) if isinstance(t, list) else {t}


def _match(system: Dict[str, Any], team: str, model: str) -> bool:
    return team in _teams(system) and any(fnmatchcase(model, p) for p in system["models"])


def build_inventory(cfg: Dict[str, Any], usage: List[Dict[str, Any]], today: Optional[date] = None) -> Dict[str, Any]:
    """Beyanlar + gözlenen kullanım (ClickHouse: ekip x model) -> envanter."""
    today = today or date.today()
    systems = []
    matched = set()
    for s in cfg.get("systems") or []:
        uc = USE_CASES[s["use_case"]]
        rows = [u for u in usage if _match(s, u["team"], u["model"])]
        matched |= {(u["team"], u["model"]) for u in rows}
        entities = sorted({e for u in rows for e in u.get("entities", [])})
        warnings = []
        if uc["risk"] == "minimal" and s.get("decides_about_people"):
            warnings.append("Kişiler hakkında karar veriliyor ama kullanım 'minimal' beyan edilmiş: "
                            "Ek III kapsamı (işe alım, kredi, sigorta...) gözden geçirilmeli.")
        if uc["risk"] != "prohibited" and not rows:
            warnings.append("Bu dönemde trafik görülmedi (model / ekip beyanı güncel mi?).")
        if any(u.get("external_with_pii", 0) for u in rows):
            warnings.append("Kişisel veri yurt dışı modele gitmiş: KVKK md. 9 aktarım dayanağı gerekli.")
        systems.append({
            "id": s["id"], "name": s["name"], "owner_team": s["owner_team"], "models": s["models"],
            "purpose": s["purpose"], "use_case": s["use_case"], "use_case_label": uc["label"],
            "risk": uc["risk"], "risk_label": RISK_LABELS[uc["risk"]], "legal_ref": uc["ref"],
            "applies_from": uc["applies_from"],
            "in_force": date.fromisoformat(uc["applies_from"]) <= today,
            "obligations": obligations(s["use_case"]), "warnings": warnings,
            "observed": {"requests": sum(u["requests"] for u in rows), "users": sum(u["users"] for u in rows),
                         "entities": entities, "destinations": sorted({u["destination"] for u in rows})},
        })
    undeclared = [
        {**u, "risk": "unclassified", "risk_label": RISK_LABELS["unclassified"],
         "action": "Bu kullanımı inventory.yaml'da bir sisteme bağlayın ve kullanım amacını beyan edin."}
        for u in usage if (u["team"], u["model"]) not in matched]
    systems.sort(key=lambda s: (RISK_ORDER[s["risk"]], s["name"]))
    counts = {r: sum(1 for s in systems if s["risk"] == r) for r in ("prohibited", "high", "limited", "minimal")}
    counts["unclassified"] = len(undeclared)
    return {"disclaimer": DISCLAIMER, "as_of": today.isoformat(), "summary": counts,
            "systems": systems, "undeclared": undeclared}


# ---------------- VERBİS taslağı ----------------

# Telveguard veri türü -> VERBİS veri kategorisi. API anahtarları / token'lar kişisel veri değildir;
# parola "İşlem Güvenliği" kategorisindedir.
VERBIS_CATEGORIES = {
    "TCKN": "Kimlik", "VKN": "Kimlik", "PERSON": "Kimlik",
    "PHONE_TR": "İletişim", "EMAIL_ADDRESS": "İletişim",
    "IBAN_TR": "Finans", "CREDIT_CARD": "Finans",
    "LOCATION": "Lokasyon", "PLATE_TR": "Diğer (araç plakası)",
    "SECRET_PASSWORD": "İşlem Güvenliği",
}
PROVIDER_COUNTRY = {"OpenAI": "ABD", "Anthropic": "ABD", "Google": "ABD", "Mistral": "Fransa (AB)",
                    "Cohere": "Kanada"}
TO_LEGAL = "Hukuk birimi belirleyecek"


def build_verbis(cfg: Dict[str, Any], rows: List[Dict[str, Any]], retention: str) -> Dict[str, Any]:
    """rows: ClickHouse'tan (entity, destination, provider, team, requests). Kategori başına bir satır."""
    systems = cfg.get("systems") or []
    by_cat: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        cat = VERBIS_CATEGORIES.get(r["entity"])
        if cat is None:
            continue  # kişisel veri değil (API anahtarı, kurum adı...)
        c = by_cat.setdefault(cat, {"types": set(), "teams": set(), "providers": set(),
                                    "external": False, "requests": 0})
        c["types"].add(r["entity"])
        c["teams"].add(r["team"])
        c["requests"] += int(r["requests"])
        if r["destination"] == "external":
            c["external"] = True
            c["providers"].add(r["provider"])
    out = []
    for cat, c in sorted(by_cat.items()):
        related = [s for s in systems if _teams(s) & c["teams"]]   # bu kategoriyi gönderen ekiplerin sistemleri
        purposes = sorted({s["purpose"] for s in related})
        subjects = sorted({g for s in related for g in s.get("data_subjects", [])})
        providers = sorted(c["providers"])
        out.append({
            "veri_kategorisi": cat,
            "tespit_edilen_turler": sorted(c["types"]),
            "isleme_amaclari": purposes or [TO_LEGAL],
            "veri_konusu_kisi_gruplari": subjects or [TO_LEGAL],
            "alici_gruplari": ["Yapay zekâ hizmet sağlayıcıları (veri işleyen)"] if providers else ["Kurum içi"],
            "yurt_disina_aktarim": "Evet" if c["external"] else "Hayır",
            "aktarilan_ulkeler": sorted({PROVIDER_COUNTRY.get(p, "Bilinmiyor - sözleşmeye bakın") for p in providers}),
            "saglayicilar": providers,
            "aktarim_dayanagi_kvkk_9": TO_LEGAL + " (yeterlilik / standart sözleşme + 5 iş günü içinde Kurul'a "
                                        "bildirim / BCR / istisnai hal)" if c["external"] else "-",
            "azami_saklama_suresi": retention,
            "gozlenen_istek": c["requests"],
        })
    return {"disclaimer": DISCLAIMER, "rows": out,
            "notes": ["Maskelenerek giden veri de 'aktarım' sayılabilir; değerlendirme hukuk birimindedir.",
                      "Veri güvenliği tedbirleri: maskeleme, denetim kaydı (ham prompt saklanmaz), erişim "
                      "kontrolü (OIDC) - VERBİS 'teknik tedbirler' başlığına eklenebilir."]}


VERBIS_COLUMNS = [
    ("veri_kategorisi", "Veri kategorisi"), ("tespit_edilen_turler", "Tespit edilen veri türleri"),
    ("isleme_amaclari", "İşleme amaçları"), ("veri_konusu_kisi_gruplari", "Veri konusu kişi grupları"),
    ("alici_gruplari", "Alıcı grupları"), ("yurt_disina_aktarim", "Yurt dışına aktarım"),
    ("aktarilan_ulkeler", "Aktarılan ülkeler"), ("saglayicilar", "Sağlayıcılar"),
    ("aktarim_dayanagi_kvkk_9", "Aktarım dayanağı (KVKK md. 9)"), ("azami_saklama_suresi", "Azami saklama süresi"),
    ("gozlenen_istek", "Gözlenen istek"),
]


def verbis_csv(report: Dict[str, Any]) -> str:
    buf = io.StringIO()
    buf.write("\ufeff")
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow([report["disclaimer"]])
    w.writerow([label for _, label in VERBIS_COLUMNS])
    for r in report["rows"]:
        w.writerow([_csv_safe(", ".join(v) if isinstance(v, list) else v) for v in (r[k] for k, _ in VERBIS_COLUMNS)])
    return buf.getvalue()
