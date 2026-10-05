# Değişiklik günlüğü

## Yayımlanmamış

### Gateway (Docker imajı / Helm chart)

- Anlık bildirim (`notify`): engellenen istek, sızan sır, kota aşımı, gölge AI uyarısı Slack,
  Microsoft Teams (Workflows, Adaptive Card) ya da genel webhook'a (SIEM). Kanal başına koşul
  (`actions`, `rules`, `entity_in`, `teams`, `sources`) ve tekrar bastırma (`cooldown_seconds`).
  Mesajda metin yoktur, yalnızca veri türleri; adres `*_WEBHOOK_URL` ortam değişkeninden okunur.
  Gönderim arka plandadır, isteği bekletmez.
- `POST /v1/notify/test` (kanallara deneme mesajı), `telveguard_notifications_total` metriği.
- Yönetim konsolu: `#olaylar?event=<id>` bağlantısı tek olayı açar (bildirimlerdeki "Konsolda aç").
- Görsel ve PDF ekleri taranır (`attachments`): görseller Tesseract OCR (`tur+eng`), PDF'ler metin
  katmanı + taranmış sayfa / gömülü görsel OCR'ı; metin dosyaları. Bulunan veri türleri aynı
  kurallardan geçer, görsele gizli injection da yakalanır. Maskeleme: görselde alan karartılır
  (üstüne yer tutucu, EXIF silinir), PDF modele maskeli metni olarak gider. Üç API biçimi ve
  Claude Code araç sonuçlarındaki görsel / PDF'ler dahil.
- Taranamayan ek (uzak adres, file_id, şifreli PDF, desteklenmeyen tür): yurt dışı hedefte
  `unscannable: allow | alert | block`, kayıtta `ek-taranamadi` kuralı.
- `telveguard_attachments_total`, `telveguard_attachment_scan_seconds` metrikleri; simülatör
  cevabında `attachments`.
- `POST /v1/embeddings` (OpenAI biçimi): RAG indeksleme trafiğinde kişisel veri maskeleme, politika,
  kota, denetim kaydı ve Röntgen'de ayrı kırılım. Injection taranmaz (embedding modeli talimat
  izlemez); token dizisi girdisi taranamaz sayılır. Sağlayıcı tipleri `openai` ve `azure`
  (klasik `deployments` dahil) embeddings'i yönlendirir; simülatörde `?format=embeddings`.
- KVKK md. 11 ilgili kişi başvurusu: konsolda **Başvuru** sekmesi ve `POST /v1/subjects/search`.
  Kişinin TCKN / VKN / IBAN / kart / telefon / e-posta / plakasının geçtiği istekler ve akıbeti
  (yurt dışına maskesiz / maskeli, kurum içi, engellendi), alıcı sağlayıcı ve ülke, yazdırılabilir
  cevap taslağı. Ham değer saklanmaz: tanımlayıcıların HMAC özeti (`TELVEGUARD_SUBJECT_HASH_KEY`)
  denetim kaydına `subject_hashes` olarak yazılır; anahtar yoksa kapalı.
- **Şema değişikliği:** `audit.subject_hashes` (+ bloom filter indeksi). Mevcut kurulumda
  `clickhouse/migrations/0.3.0-subject-hashes.sql` bir kez çalıştırılmalı. Helm: `secrets.subjectHashKey`.
- Docker imajına Tesseract (Türkçe + İngilizce) eklendi (~110 MB); `pillow`, `pypdfium2` bağımlılıkları.

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
