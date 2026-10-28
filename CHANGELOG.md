# Değişiklik günlüğü

## 0.6.0 — 2026-10-28

### Koruma

- Bölünmüş TCKN ve VKN (`telveguard-core` ve tarayıcı eklentisi): rakamlar arasında tek boşluk, tire
  ya da nokta olan yazım (`100 000 001 46`, `100-000-001-46`) yakalanır. Ayraçla devam eden rakam
  varsa (sayı tablosu) 11 hanelik pencere seçilmez. Bağlamsız bölünmüş TCKN 0.8 skor alır (kart /
  IBAN çakışmada kazanır); "TC", "T.C.", "TCKN", "kimlik no" yakındaysa 1.0. VKN zaten
  "vergi no" / "vkn" bağlamı ister.
- Kurumsal sözlük ContextForge'da: eklenti sözlüğü gateway'den çeker (`GET /v1/contextforge/dictionary`,
  `CONTEXTFORGE_TOKEN`; Helm Secret anahtarı `contextforge-token`) ya da `dictionary_file` ile politika
  dosyasından okur. `KURUM_*` varsayılan olarak araç çıktısında maskelenir ve dış araca gönderilemez.
  Gateway'e ulaşılamazsa eldeki sözlükle devam edilir.
- ContextForge'da araç çağrıları arası yer tutucu vault'u (Redis; `TELVEGUARD_VAULT_REDIS_URL`,
  `TELVEGUARD_VAULT_KEY`): aynı değer aynı kullanıcı için her çağrıda aynı `[TCKN_n]`; kurum içi araca
  giden argümanlardaki yer tutucular gerçek değere çevrilir (`unmask_tool_args`, dış araca asla).
  Kullanıcı + tenant kapsamı, değerler AES-GCM ile şifreli, Redis anahtarlarında kullanıcı adı ve ham
  değer yok, 8 saat TTL. Redis'e ulaşılamazsa araç çıktısı engellenir. Önceden agent'ın bir araçtan
  aldığı `[TCKN_1]`'i başka bir araca vermesi iş akışını kırıyordu.
- Aynı numaranın farklı yazımları tek yer tutucu (gateway, ContextForge, tarayıcı eklentisi):
  `391 417 776 94` ve `39141777694` ikisi de `[TCKN_1]`; telefon, IBAN, kart, VKN da.
- Artımlı streaming (`STREAM_MODE=incremental`, Helm `streamMode`; varsayılan `buffer`): cevap akarken
  taranır, sızıntı gizlenir, yer tutucular geri açılır; ilk token cevabın tamamını beklemez. Cevabın
  sonundaki son kelime, son 64 karakter (`STREAM_HOLDBACK_CHARS`), yarım yer tutucu ve sınırı kesen
  bulgu bekletilir: sonuç her parçalamada tamponlu yolla aynıdır. Araç argümanları blok bitince tek
  parça. Uygulanan `block` çıktı kuralı varsa tamponlanır. Usage streaming'de de okunur (OpenAI chat'te
  `stream_options.include_usage` gateway ekler; istemci istemediyse usage parçası ona gitmez): Röntgen,
  kota ve maliyet doğru. Denetim kaydı akış bitince yazılır; istemci koparsa `stream_aborted`.
  Yeni metrik: `telveguard_first_token_seconds` (`mode`: incremental | buffered).
- Sözlük ayrıştırması `telveguard-core`'a taşındı (`telveguard_core.dictionary`); `gateway/app/dictionary`
  aynı adları dışa aktarmaya devam eder.

### Performans

- İstek taraması parça parça ve önbellekli (`telveguard-core` `analyze_parts`, `scan_parts`;
  `TELVEGUARD_SCAN_CACHE_SIZE`, worker başına 4096 parça): değişmeyen parçalar (önceki turlar, sistem
  istemi, araç tanımları) yeniden taranmaz. Claude Code tarzı 286 KB istekte sonraki tur 278 ms -> 8 ms.
  Önbellek anahtarı metnin SHA-256 özeti + tanıyıcı kuşağı (ham metin saklanmaz); sözlük / istisna
  değişince boşalır. Parça sınırını aşan bulgular (iki mesaja bölünmüş telefon, sonraki mesajdaki VKN'nin
  "vergi no:" bağlamı, bölünmüş saldırı cümlesi) sınır pencereleriyle bulunur: sonuç tüm metni tek seferde
  taramakla aynı (300'er rastgele senaryoyla doğrulanır). Kapanmamış private key artık sonraki
  parçalardaki bulguları saymadan bırakmıyor.
- Maskeleme parçaları yeniden taramaz (analizdeki bulgular kullanılır; önbelleksiz de ~%36 daha hızlı).
- `SCAN_THREAD_MIN_BYTES` (64 KB) üstündeki istekler thread'de taranır: büyük istek o worker'daki diğer
  istekleri ve akan stream'leri dondurmaz (GIL nedeniyle throughput artmaz; ölçek worker / pod sayısıyla).
- Artımlı streaming yeni metin 32 karakter birikince tarar (`STREAM_SCAN_EVERY_CHARS`): her delta'da
  pencereyi yeniden taramak tamponlu yolun ~40 katı CPU harcıyordu (10 KB cevap 148 -> 23 ms). Sonuç
  aynı; içeriği boş kalan delta olayları istemciye gönderilmez.
- ContextForge vault'u Redis pipeline'ıyla: bir araç çıktısındaki tüm değerler 1-3 gidiş-dönüşte
  (önceden değer başına sıralı 2-4; 50 değerde ~200). Geri açma tek gidiş-dönüş. Araç çıktısı bir kez taranır.
- `telveguard_scan_duration_seconds` kovaları 5 sn'ye kadar (önceden 0,25 sn üstü `+Inf`'e düşüyordu).

### Yükseltme notları

- `telveguard-contextforge` ve `telveguard-agent` `telveguard-core>=0.6.0` ister (sözlük modülü
  `telveguard_core.dictionary`, `canonical_value`, parça bazlı tarama).
- Bölünmüş TCKN artık yakalanır: önceden maskesiz geçen `100 000 001 46` gibi yazımlar maskelenir.
  Sayı listeleri yoğun ekiplerde ilk hafta yanlış pozitifleri Röntgen'de izleyin.
- ContextForge sözlüğü (opsiyonel): gateway'de `CONTEXTFORGE_TOKEN` (Helm Secret anahtarı
  `contextforge-token`), ContextForge'da aynı değer `TELVEGUARD_CONTEXTFORGE_TOKEN`, eklentide
  `dictionary_gateway_url`. `KURUM_*` eklentinin varsayılan maske ve dış araç listelerinde: özel
  `mask_entities` / `exfil_block_entities` tanımladıysanız ekleyin.
- ContextForge vault'u (opsiyonel): `TELVEGUARD_VAULT_REDIS_URL` ve `TELVEGUARD_VAULT_KEY` (en az 32
  karakter; değişirse eski kayıtlar açılamaz). Redis'e ulaşılamazsa araç çıktısı engellenir.
- Artımlı streaming varsayılan olarak kapalı (`streamMode: buffer`); önce bir ekipte deneyin.
- Denetim olayındaki yeni `stream_aborted` alanı ClickHouse'a yazılmaz (kolon yok; Kafka bilinmeyen
  alanı atlar); SIEM / Kafka tüketicilerine gider.

## 0.5.0 — 2026-10-27

### Güvenlik

- İstek gövdesi sınırı (`MAX_REQUEST_BYTES`, 32 MB; Helm `maxRequestBytes`): aşan istek gövde
  okunmadan 413. İstek başına taranan ek sayısı sınırlı (`attachments.max_count`, 50; fazlası
  taranamaz sayılır). Önceden tek bir istemci sınırsız gövde ve OCR işiyle belleği / CPU'yu doldurabiliyordu.
- Kafka bağlantı güvenliği: `KAFKA_SECURITY_PROTOCOL` (SSL / SASL_SSL / SASL_PLAINTEXT), SASL
  (SCRAM / PLAIN), kurum içi CA ve karşılıklı TLS (Helm `audit.kafka.*`, şifre `kafka-sasl-password`).
- Tarayıcı eklentisi olay ucu hız sınırlı (`SHADOW_AI_USER_PER_MIN`, `SHADOW_AI_GLOBAL_PER_MIN`):
  token MDM ile herkese dağıtıldığı için sahte olay seli kaydı ve bildirim kanallarını doldurabiliyordu.
- Acil yayın kapatılabilir (`POLICY_EMERGENCY=0`, Helm `policy.store.emergency`); acil yayın ve
  geri alma (tek kişiyle yayın) bildirim kanallarına düşer (`politika:acil-yayin`, `politika:geri-alma`).
- Azure sağlayıcısında model adı URL yoluna kodlanarak eklenir: `gpt-../../...` gibi bir ad kurumun
  Azure anahtarıyla başka bir uca istek attırabiliyordu.
- Konsol ve Kurum Asistanı sayfalarında CSP (yalnızca sayfanın kendi betiği, istekler yalnızca
  gateway'e, çerçeveleme yasak); tüm cevaplarda `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`. Git sunucusundan dönen bağlantı yalnızca `http(s)` ise bağlantı olur.
- `/metrics` isteğe bağlı token'la (`METRICS_TOKEN`, Helm `metrics.requireToken`; ServiceMonitor aynı token'ı kullanır).
- `/v1/agent/check` gözlemdeki kuralları (`monitored_rules`, `would_action`) döndürmez: her kullanıcı
  hangi kuralın henüz uygulanmadığını yoklayabiliyordu.
- İsteğin bilinen metin alanları dışında kalan kısmı da taranır ve maskelenir: araç tanımları
  (`tools`), yapılandırılmış çıktı şeması (`response_format`, `text.format`), `metadata`, `user`,
  istem değişkenleri, bilinmeyen içerik blokları; 10+ haneli sayılar metin gibi. Önceden kişisel
  veri bu alanlara konarak yurt dışı modele maskesiz gönderilebiliyordu. Yapı değerleri (`model`,
  `id`, araç adı), imzalı `thinking` blokları ve ek verisi hariç. Mesaj listesindeki bilinmeyen
  bloklar injection için de taranır.
- Görünmez karakterle kaçırma (`telveguard-core` ve tarayıcı eklentisi): tarama, Unicode biçim
  karakterleri (sıfır genişlikli boşluk, yumuşak tire, yön işaretleri, etiket karakterleri)
  atılıp NFKC uygulanmış metinde yapılır; ofsetler orijinal metne eşlenir, maske araya
  sıkıştırılmış karakterler dahil tüm değeri kapatır. Önceden `1000<U+200B>0000146` TCKN,
  IBAN, kart ve sır tespitinden kaçıyordu. İlgili kişi araması da aynı normalleştirmeyi kullanır.
- Politika doğrulaması sıkılaştı (`telveguard-core`): `teams` / `entity_in` boş olmayan metin
  listesi, `destination` `internal` / `external`, `injection_score_gte` 0-1 arası sayı, `name` /
  `message` metin. Önceden `injection_score_gte: "0.5"` gibi bir değer yüklenip istek anında hata
  veriyor, `entity_in: TCKN` kuralı sessizce etkisiz bırakıyordu.
- Konsol taslağında YAML takma adları (`&` / `*`) ve bilinmeyen veri türü adları reddedilir
  (küçük bir metnin bellekte üstel büyümesi; `TCKNN` gibi yazım hataları).
- `OIDC_ADMIN_GROUP` tanımlıyken politika değişikliği yalnızca kurum hesabıyla: statik yönetici
  token'ındaki ad beyan olduğundan başkası adına onaylanıp dört göz atlatılabiliyordu.
  `POLICY_STATIC_TOKEN_WRITES=1` ile bilinçli istisna.
- Git yansıtma: commit mesajındaki alanlar tek satıra indirgenir (notla sahte
  `Telveguard-Policy-Version:` satırı eklenemez); token `repr` çıktısında görünmez; adres
  varsayılan olarak yalnızca `https://` (`POLICY_GIT_ALLOW_HTTP=1` yalnızca yerel test).
- ICAP: sıkıştırılmış gövde en fazla `ICAP_MAX_BODY` kadar açılır; gövde ayrıştırma hataları bağlantıyı
  düşürmez, "okunamadı" sayılır (proxy'nin bypass'ı taramayı atlamasın); parçalar sınırlı dilimlerle
  okunur; sınırı aşan gövde varsayılan olarak durdurulur (`ICAP_OVERSIZE=block`).
- `telve`: gateway adresi yalnızca `http(s)://`.
- Guardrail: çağıranın bildirdiği `destination: internal` varsayılan olarak yok sayılır (yalnızca
  daha sıkı `external` geçerli); istemci bu alanı istek bazında verebiliyorsa yurt dışı modele
  maskesiz veri gidebiliyordu. Kurum içi takma adlar politikadaki `destinations.internal`'a;
  eski davranış için `GUARDRAIL_TRUST_DESTINATION=1`. Konsoldaki `routing` kuralları da aynı
  doğrulamadan geçer. Redis'siz kurulumda bellekteki oturum sayısı sınırlı.

### Yükseltme notları

- Helm: `policy.store.enabled` ve birden fazla süreç (replica / worker / autoscaling) varken
  `quota.redisUrl` zorunlu; Redis'siz onay kilidi worker'lar arasında geçmiyordu.
- 32 MB'tan büyük istek gönderen istemciler için `maxRequestBytes`'ı artırın.
- Guardrail'de `additional_provider_specific_params: { destination: internal }` kullanıyorsanız
  takma adı politikadaki `destinations.internal`'a ekleyin ya da `GUARDRAIL_TRUST_DESTINATION=1`.
- Daha sıkı politika doğrulaması: yüklenemeyen özel politika artık gateway açılışında hata verir
  (önceden istek anında hata verebiliyor ya da kural sessizce etkisiz kalıyordu). Yükseltmeden önce
  `PolicyEngine("politika.yaml")` ile deneyin.
- ICAP: `ICAP_MAX_BODY`'yi aşan gövde artık durdurulur; eski davranış `ICAP_OVERSIZE=allow`.

### Gateway (Docker imajı / Helm chart 0.5.0)

- Onaylanan politika sürümünü Bitbucket Data Center'a yansıtma (`POLICY_GIT_*`, Helm
  `policy.store.git.*`): onay, acil yayın ve geri alma depoya commit (ya da dal + PR) olarak yazılır;
  kim yazdı / kim yayına aldı / gerekçe commit mesajında, şablon ayarlanabilir. Dosya ConfigMap
  politikasının tamamı (kural bölümleri yerinde, yorumlar korunur) ya da yalnızca kurallar.
  `POLICY_GIT_STRICT=1` ile Git'e yazılamayan sürüm yayına girmez; aksi hâlde arka planda denenir,
  sonuç sürüm geçmişinde (`mirrored` / `mirror_failed`), konsoldan yeniden yazılabilir. Eski sürüm
  depodaki yeniyi ezmez. `GET /v1/policy/git` bağlantı denemesi, `POST /v1/policy/versions/{v}/mirror`.

## 0.4.0 — 2026-10-20

### Yükseltme notları

- Politika yüklenirken kural koşulları (`when`) doğrulanır: bilinmeyen bir koşul adı (ör. yazım
  hatası) artık sessizce yok sayılmaz, gateway başlarken hata verir. Özel politikanızı
  `PolicyEngine("politika.yaml")` ile ya da simülatörde deneyin.

### telveguard-core

- `TrPiiEngine.exempt`: (tür, değer) -> bool; eşleşen bulgular çakışma çözüldükten sonra düşülür.
- `PolicyEngine.route(ctx)` ve politikada `routing` bölümü (`name`, `when`, `to`, `mode`).
- `PolicyEngine(config=...)`: politika dosya yerine sözlükten de kurulur. Doğrulama sıkılaştı:
  geçersiz `default_action` / `mode`, adı olmayan ya da aynı adlı kurallar hata verir.
- Model izin listesi: kurallarda `model_in` / `model_not_in` (model adı, joker destekli) ve
  `declared` (AI envanterinde beyan edilmiş mi) koşulları. `Context.declared` alanı.

### Gateway (Docker imajı / Helm chart 0.4.0)

- Guardrail servisi: LiteLLM (`POST /beta/litellm_basic_guardrail_api`, Generic Guardrail API) ve
  agentgateway (`POST /v1/guardrail/agentgateway/request|response`, Guardrail Webhook API) isteği
  modele göndermeden önce ve cevabı vermeden önce Telveguard'a sorar. Gateway'in kendi yoluyla aynı
  tarama, politika, istisnalar ve maskeleme; cevapta sızıntı taraması, çıktı kuralları ve maskeyi geri
  açma. İstek ile cevap oturumla eşleşir (LiteLLM `litellm_call_id`, agentgateway `uuid()` başlığı);
  maske eşleşmesi `GUARDRAIL_SESSION_TTL` (600 sn) Redis'te ya da bellekte. LiteLLM stream'inde
  (`incremental_diff`) maske geri açılır, yarım yer tutucu `stream_holdback_chars` ile bekletilir.
  `GUARDRAIL_TOKEN` (Helm: `guardrail-token`); kayıtta `api_format=guardrail`, kural
  `guardrail:<kaynak>`. Metrikler `telveguard_guardrail_checks`, `telveguard_guardrail_session_misses`.
  Hazır yapılandırmalar `deploy/guardrail/` (LiteLLM v1.104, agentgateway v1.6 ile denendi).
- İstisna listesi (`exceptions`): kurumun kamuya açık değerleri (tahsilat IBAN'ı, destek e-postası,
  çağrı merkezi numarası) bulunmamış sayılır: maskelenmez, kurallara, kayda ve çıktı sızıntısı
  taramasına girmez. `values` biçimden bağımsız (boşluk, +90 / 0 öneki, büyük / küçük harf),
  `patterns` değerin tamamıyla eşleşir. `SECRET_*` ve `KURUM_*` istisna olamaz. Motorun tanımadığı
  değer açılışta uyarı olarak loglanır (değerin kendisi loglanmaz). `/v1/policy/info`'da sayılar.
- Akıllı yönlendirme (`routing`): eşleşen istek (ör. yurt dışı modele TCKN / IBAN) maskelenmek ya da
  engellenmek yerine `to` ile verilen kurum içi modele gider; kurallar yeni hedefe göre yeniden
  uygulanır. Hedef kurum içi değilse ya da API biçimi için kurum içi upstream yoksa yönlendirilmez.
  Gözlem modu (`mode: monitor`) desteklenir. Kayıtta kural `yonlendirme:<ad>`, cevapta
  `X-Telveguard-Routed-To` başlığı; simülatörde `routed_from`. Konsoldan düzenlenir (Politika
  sekmesinde ayrı grup). POC raporunda yönlendirilen istekler "korundu" sayılır.
  Etki analizi (`POST /v1/policy/impact`) yönlendirmeyi hesaba katar: sonuç `route`, yalnızca
  gateway'den geçen biçimlerde ve kurum içi upstream'i olan hedefte.
- Ağ tarafı (ICAP, RFC 3507 REQMOD): kurum proxy'si (Squid, ProxySG, Forcepoint, Zscaler ...)
  TLS denetimiyle çözdüğü AI isteklerini sorar; masaüstü uygulamaları ve betikler. Gövdedeki metin
  biçimden bağımsız taranır, karar geçir (204) / durdur (403; SDK'lara JSON, tarayıcıya HTML).
  Politika "maskele" diyorsa durdurulur. Kimlik proxy'nin `X-Authenticated-User` /
  `X-Authenticated-Groups` başlıklarından, yalnızca `ICAP_ALLOWED_CLIENTS`'tan. `ICAP_PORT` ile açılır.
  Kayıtta `api_format=icap`; Röntgen'de "Proxy (ICAP)", POC raporunda Gölge AI bölümünde; bildirim
  kaynağı `network`. Metrik `telveguard_icap_checks`. Helm `icap.*` (ayrı `-icap` Service,
  NetworkPolicy ipBlock). Yerel deneme: `docker-compose.icap.yml`, Squid örneği `deploy/icap/squid.conf`.
- Konsoldan politika yönetimi (**Politika** sekmesi, `POLICY_STORE=clickhouse`): taslak, canlı
  doğrulama ve fark, geçmiş trafiğe etki analizi (`POST /v1/policy/impact`), dört göz onayı, acil
  yayın, geri alma. Sürümler ClickHouse'ta (`policy_versions`, `policy_events`, yalnızca ekleme);
  onaylanan sürüm pod'lara yeniden başlatmadan yayılır. Uçlar: `GET /v1/policy/store`,
  `GET /v1/policy/versions/{v}`, `POST /v1/policy/validate`, `POST /v1/policy/versions`,
  `POST /v1/policy/versions/{v}/approve|reject|apply`. Statik yönetici token'ında kişi
  `X-Telveguard-Actor` başlığından. Helm `policy.store.*`.
- `declared` koşulu `inventory.yaml`'dan hesaplanır: kullanıcının ekiplerinden biri için bu
  modeli içeren bir sistem beyan edilmişse `true`. Envanter boşsa koşul eşleşmez.
- Simülatör cevabında ve Politika deneme ekranında `declared`.
- Varsayılan politikada yorum satırı olarak model izin listesi örnekleri.
- `GET /v1/shadow-ai/dictionary` (`SHADOW_AI_TOKEN`): kurumsal sözlüğün tarayıcı sürümü. Terimler
  tuzlu SHA-256 özeti (ilk 64 bit), düzenli ifadeler olduğu gibi; ETag ile 304.
- Gölge AI olaylarında `KURUM_*` veri türleri ve `trigger: file` ("Tarayıcı: dosya eklerken").
- POC raporu: konsolda **POC raporu** sekmesi (`#rapor`) ve `GET /v1/reports/poc?days=`. Riskli
  istekler korundu / gözlemde korunurdu / korumasız; risk türleri, KVKK md. 9 (veri türü ×
  sağlayıcı × ülke), ekipler, gölge AI, örnek olaylar (kullanıcı adı yok) ve politika YAML'ı ile
  öneriler. Yazdırılabilir / PDF.
- `policies/poc.yaml`: varsayılan politikanın gözlem modundaki hâli (sırlar uygulanır).
- `scripts/demo_traffic.py`: gerçek politikadan geçen, geçmiş tarihli demo trafiği ve gölge AI
  olayları (`auth_source = demo`, `--purge` ile silinir).
- KVKK ve VERBİS raporlarında `text-embedding-*` modelleri OpenAI olarak tanınır.
- Gölge AI olaylarında `redirected` aksiyonu ve `justification` (yalnızca seçenekler); POC raporunda
  onaylı araca yönlendirme, "yine de" gerekçeleri ve yanlış alarm oranı yüksek tespitler için öneri.
- Demo kiti: `scripts/demo_reset.sh` (tek komut), `docker-compose.demo.yml`, `demo/eticaret/`
  (e-ticaret / açık artırma: politika, gözlem politikası, AI envanteri, örnek dosyalar),
  `demo_traffic.py --profile`, `/asistan` demo sohbet sayfası (`DEMO_ASSISTANT=1` ve header kimliğiyle),
  `docs/demo.md` kılavuzu.

- Kod asistanı hook'ları için `POST /v1/agent/check`: Cursor / Claude Code'un prompt'u, okuduğu
  dosya, çalıştıracağı komut, MCP / web aracı argümanı ve araç çıktısı kullanıcının kendi kimliğiyle
  politikadan geçer; karar `allow | warn | mask | block`. Hook metni değiştiremiyorsa "maskele"
  kararı durdurmaya döner; Claude Code araç çıktısı maskeli döner. Cursor isteklerinin hedefi her
  zaman yurt dışıdır (veri önce Cursor'un sunucularına gider). Denetim kaydında `api_format`
  `cursor` / `claude-code`; temiz dosya okumaları kayda yazılmaz. Metrik: `telveguard_agent_checks`.
- `GET /v1/agent/config`: `telve setup` / `telve login` için kimlik modu ve OIDC cihaz akışı
  bilgisi (`OIDC_AGENT_CLIENT_ID`, Helm: `auth.oidc.agentClientId`).

### telveguard-agent (yeni paket, `telve`)

- `telve setup / login / token / install / uninstall / hook / check / doctor`. OIDC cihaz akışıyla
  giriş, sessiz token yenileme, Claude Code `apiKeyHelper`.
- `telve install cursor`: `beforeSubmitPrompt`, `beforeReadFile`, `beforeTabFileRead`,
  `beforeShellExecution`, `beforeMCPExecution`.
- `telve install claude [--route]`: `UserPromptSubmit`, `PreToolUse` (Bash, web, MCP), `PostToolUse`
  (Read, Grep, Bash, web, MCP çıktısı maskelenir). `--route` model trafiğini de Telveguard'a verir.
- `--scope enterprise` / `--print`: MDM ile dağıtım; Claude Code için kurumun
  `managed-settings.json`'una dokunmayan `managed-settings.d/telveguard.json`.
- Gateway'e ulaşılamazsa `fail_closed` (kurumsal yapılandırma) durdurur; yoksa telveguard-core ile
  yerel tarama yapılır.

### Tarayıcı eklentisi

- İstisnalar (`exceptions`) eklentide de geçerli: sözlükle aynı uçtan (`GET /v1/shadow-ai/dictionary`,
  `exceptions` alanı) değerler tuzlu özet, düzenli ifadeler olduğu gibi gelir; istisna değer
  yapıştırırken uyarı çıkarmaz ve maskelenmez. Sürüm (ETag) istisnalar değişince de değişir.
  Popup'ta istisna sayısı.
- Kayıtta görünen kişi: MDM'de `user` yoksa Chrome'da oturum açmış profilin e-postası
  (`identity`, `identity.email` izinleri; MDM ile zorunlu kurulumda onay sorulmaz), o da yoksa
  `unknown`. Popup'ta "Kayıtta görünen" satırı. `dev_extension.sh` artık sabit `demo.kullanici`
  yazmaz (5. argümanla verilebilir).
- Kurum Asistanı demo sayfasında kullanıcı alanı (tarayıcıda hatırlanır); sabit `demo.kullanici` kalktı.

- Kurumsal sözlük: proje adları, müşteri unvanları, iç sunucu adları yapıştırma, gönderim ve
  dosyalarda yakalanır, `[KURUM_PROJE_1]` olarak maskelenir. Sözlük saatte bir gateway'den çekilir;
  popup'ta terim sayısı ve son kontrol zamanı.
- Dosya ekleme: sürükle-bırak, dosya seçme ve dosya yapıştırmada metin dosyaları (5 MB'a kadar)
  taranır; "Maskeleyerek ekle" siteye maskeli kopyayı verir. Yeni MDM ayarı `unscannableFiles`
  (`allow` | `block`): PDF, görsel ve Office belgeleri.
- Onaylı araca yönlendirme (MDM `sanctionedAiUrl`, `sanctionedAiName`, `showBanner`): uyarı
  pencerelerinde "<ad> ile devam et" (metin panoya), AI sitelerinde bilgilendirme bandı.
- "Yine de" için gerekçe (MDM `requireJustification`, varsayılan açık): müşteri onayı, test verisi,
  yanlış alarm, diğer.
- `scripts/package_extension.sh`: gateway adresiyle paketleme; mağaza için `.zip`, kendi sunucunuz
  için imzalı `.crx` + `update.xml` ve eklenti kimliği.

## 0.3.0 — 2026-10-05

PyPI paketlerinde (telveguard-core, telveguard-contextforge) kod değişikliği yoktur; sürüm
numarası diğer bileşenlerle birlikte güncellendi. Yenilikler gateway, Helm chart ve Docker imajındadır.

### Yükseltme notları

- **ClickHouse şeması değişti.** Mevcut kurulumda gateway'i güncellemeden önce ya da sonra,
  yazma yetkili kullanıcıyla bir kez çalıştırın (yeni kurulumda `init.sql` zaten içerir):
  `clickhouse-client --multiquery < clickhouse/migrations/0.3.0-subject-hashes.sql`.
  Dosyadaki `kafka_broker_list` / topic / group değerlerini kendi `audit_queue`'nuzla aynı yapın.
- **Docker imajı ~110 MB büyüdü** (OCR için Tesseract, Türkçe + İngilizce). Air-gapped ortamda
  imajı derlerken apt deposu iç aynadan kullanılmalı.
- **Varsayılan politikada yeni bölümler:** `attachments` (taranamayan ek: `alert`), `notify`
  (adres ortam değişkeni boşsa kanallar kapalı) ve örnek terimlerle `dictionary` +
  `kurum-terimleri-yurtdisi-maskele`. Kendi politikanızı kullanıyorsanız bu bölümleri ekleyin;
  `dictionary` örneklerini kendi terimlerinizle değiştirin.
- İlgili kişi araması için `TELVEGUARD_SUBJECT_HASH_KEY` (Helm: `secrets.subjectHashKey`)
  tanımlanmalı; yalnızca tanımlandıktan sonraki istekler aranabilir.

### Gateway (Docker imajı / Helm chart 0.3.0)

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
- Kurumsal sözlük (`dictionary`): proje kod adları, müşteri unvanları, iç sunucu adları gibi
  terimler (liste, dosya ya da düzenli ifade) `KURUM_*` türüyle tespit edilip kurallardan geçer;
  yurt dışı modele maskeli gider, cevapta geri açılır. Türkçe büyük / küçük harf ve boşluk farkından
  bağımsız, tam kelime; on binlerce terim ağaç biçimli tek düzenli ifadeyle taranır. Kişisel veri
  sayılmaz (KVKK raporu ve VERBİS dışında). Varsayılan politikada örnek sözlük ve
  `kurum-terimleri-yurtdisi-maskele` kuralı.
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
