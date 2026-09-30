# Değişiklik günlüğü

## 0.2.1 — 2026-09-30

PyPI paketlerinde (telveguard-core, telveguard-contextforge) kod değişikliği yoktur; sürüm
numarası diğer bileşenlerle birlikte güncellendi. Yenilikler gateway, Helm chart ve eklentidedir.

- Yönetim konsolu: Olaylar (denetim kaydı gezgini, Röntgen'den tıklayarak geçiş) ve Politika deneme ekranı.
- Sağlayıcı yönlendirmesi (`providers`): Azure OpenAI, Gemini, Mistral, Anthropic, birden fazla
  kurum içi sunucu; KVKK / VERBİS raporunda sağlayıcı adı ve ülkesi.
- Tarayıcı eklentisi: gönderim anında kontrol (Enter / gönder düğmesi; elle yazılan metin de).
- README: kendi ürününüze entegrasyon rehberi (SDK'lar, kimlik, hata kodları, CI'da politika testi).

## 0.2.0 — 2026-09-29

### Paketler (PyPI)

**telveguard-core**
- Sır tespiti: parola tanıyıcısında yanlış pozitifler azaltıldı (`password=password`, `${VAR}`,
  tip ifadeleri, yer tutucular); `"password": "..."` (JSON) artık yakalanıyor. Maskeleme idempotent.
- Politika: çıktı kuralları (`output_rules`), çoklu ekip eşleşmesi (kullanıcının herhangi bir ekibi;
  kısıtlayıcı kuraldan grup sırasıyla kaçılamaz), `quotas` bölümü.
- LLM Guard: model lokal dizinden internetsiz yüklenir (`LLM_GUARD_MODEL_PATH`).
- **Düzeltme:** LLM Guard'ın tespit ettiği injection'lar engellenmiyordu (`risk_score` olasılık gibi
  okunuyordu); karar artık `is_valid`'e göre.

**telveguard-contextforge**
- Araç izin listesi (`tool_access`): ekip / kullanıcı bazlı allow / deny, deny her zaman kazanır;
  varsayılan yapılandırma yıkıcı araçları (`*delete*`, `*drop*`, `*destroy*`) kapatır.
- Çağıran kullanıcı ve servis hesabı (agent) kaydedilir.

### Gateway (Docker imajı / Helm chart 0.2.0)

- Anthropic `/v1/messages` (Claude SDK, **Claude Code**) ve OpenAI `/v1/responses` desteği.
- OIDC / JWT kimlik doğrulama; yönetim uçlarına OIDC grubuyla erişim (`OIDC_ADMIN_GROUP`).
- Çıktı koruması: modelin ürettiği yeni kişisel veri / sır gizlenir ya da cevap engellenir.
- Ekip kota / hız sınırı (Redis ile tüm pod'lar ortak).
- Prometheus metrikleri (`/metrics`).
- AI envanteri + EU AI Act risk sınıflandırması (Digital Omnibus takvimi) ve VERBİS taslağı.
- Gölge AI tarayıcı eklentisi (`extension/`, Chrome / Edge MV3) ve olay toplama ucu.
- Düzeltmeler: Kafka kesintisi istekleri 500'e çevirmiyor; tamponlu chat stream'inde araç
  çağrıları kaybolmuyor; JWKS, IdP açılışta erişilemezse yanıltıcı 401 yerine 503 döner.

## 0.1.0 — 2026-09-28

- İlk sürüm: OpenAI uyumlu LLM gateway, Türkçe PII ve sır tespiti / maskeleme, prompt injection
  tespiti, YAML politika (gözlem modu, simülatör), Kafka → ClickHouse denetim kaydı, AI Kullanım
  Röntgeni, KVKK yurt dışı aktarım raporu, IBM ContextForge eklentisi, OKD Helm chart'ı.
