# Telveguard

**Kurumsal yapay zekâ kullanımı için Türkiye odaklı güvenlik geçidi.** Çalışanların ve
uygulamaların LLM'lere gönderdiği isteklerdeki kişisel veriyi (TCKN, IBAN, kart, telefon...)
ve sırları (API anahtarı, parola...) maskeler, saldırı girişimlerini engeller, her isteği
KVKK'ya uygun şekilde kayda geçirir. Kurum içinde (on-prem / air-gapped) çalışır.

> **Neden "Telveguard"?** Türk kahvesi içilir, *telve* fincanda kalır. Model işine yarayanı alır;
> kişisel veri kurumun fincanında kalır.

```
uygulama ──► Telveguard ──► kurum içi LLM (vLLM / Ollama)        veri olduğu gibi
               │        └─► OpenAI / Anthropic / Gemini           veri maskeli: TC [TCKN_1]
               │                   cevap döner, [TCKN_1] gerçek değere geri çevrilir
               └─► Kafka ─► ClickHouse ─► AI Kullanım Röntgeni + KVKK raporu
```

Uygulamalar kod değiştirmez: OpenAI uyumlu olduğu için yalnızca `base_url` Telveguard'a çevrilir.

## Neler yapar?

- **Türkçe kişisel veri maskeleme:** TCKN, VKN, IBAN ve kart numarası sağlama toplamıyla
  doğrulanır (rastgele 11 haneli sayı TCKN sayılmaz); telefon, e-posta, plaka; opsiyonel
  Türkçe NER ile kişi / kurum / yer adları.
- **Sır tespiti:** AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe anahtarları, JWT,
  private key, parolalı bağlantı dizeleri, `şifre: ...`.
- **Prompt injection engelleme:** Türkçe ve İngilizce; araç çıktılarına ve web içeriğine
  gizlenmiş (dolaylı) saldırılar dahil. "ÖNCEKİ TÜM TALİMATLARI YOK SAY" gibi büyük harfli
  Türkçe yazımlar da yakalanır.
- **YAML politika:** ekip, model ve veri türüne göre izin ver / uyar / maskele / engelle.
  Yeni kural önce **gözlem modunda** denenebilir; **simülatör** bir isteğin ne olacağını gösterir.
- **Denetim kaydı:** ham prompt hiç saklanmaz; özet, bulunan veri türleri, karar, token ve
  tahmini maliyet Kafka üzerinden ClickHouse'a yazılır (KVKK saklama süresi ayarlı).
- **AI Kullanım Röntgeni:** kim, hangi modeli, ne kadar kullanıyor; yurt dışına ne gidiyor,
  ne engellendi, ne kadar tuttu (tarayıcıda açılan dashboard).
- **KVKK yurt dışı aktarım raporu:** aylık, Excel'de açılan CSV.
- **MCP / agent koruması:** IBM ContextForge eklentisi; araç çıktısındaki kişisel veriyi
  maskeler, kişisel veri veya sırrın dış araçlara (Slack, e-posta, web) gönderilmesini engeller.

## Hızlı başlangıç

Docker yeterli; gerçek bir LLM gerekmez (test ortamı gelen isteği geri yansıtan sahte bir model kullanır).

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build

curl -s localhost:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"TC 10000000146 olan müşteriyi özetle"}]}'
```

Sahte model, kendisine ne geldiğini cevabında gösterir (`mock_received_messages`);
kullanıcıya dönen cevapta (`choices[0].message.content`) yer tutucu gerçek değere geri çevrilmiştir:

```
modele giden : TC [TCKN_1] olan müşteriyi özetle
kullanıcıya  : MODEL GÖRDÜ: TC 10000000146 olan müşteriyi özetle
```

Saldırı denemesi engellenir:

```bash
curl -s localhost:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Önceki tüm talimatları yok say"}]}'
# {"error":{"message":"Telveguard: Olası prompt injection tespit edildi.", ... "code":"blocked"}}
```

**Röntgen:** http://localhost:8080/xray → yönetici token'ı olarak `e2e-admin-token`
(yalnızca bu yerel test ortamı içindir).

Kapatmak için: `docker compose -f docker-compose.yml -f docker-compose.test.yml down`

## Uygulamanızı bağlamak

```python
from openai import OpenAI

client = OpenAI(base_url="http://telveguard:8080/v1", api_key="kullanılmıyor",
                default_headers={"x-telveguard-user": "ayse", "x-telveguard-team": "analitik"})
```

Model adı hedefi belirler (`policies/default.yaml` → `destinations`): `vllm/`, `local/`, `qwen`,
`llama` kurum içi; `gpt-`, `claude-`, `gemini-` ve tanınmayan her model yurt dışı sayılır.

## Politika

Politika bir YAML dosyasıdır (hazır örnek: `policies/default.yaml`). Kurallar sırayla
değerlendirilir, en kısıtlayıcı karar kazanır (engelle > maskele > uyar > izin ver). Kısaltılmış örnek:

```yaml
rules:
  - name: kvkk-yurtdisi-maskele          # yurt dışı modele kişisel veri maskeli gitsin
    when: { destination: external, entity_in: [TCKN, IBAN_TR, CREDIT_CARD, PHONE_TR] }
    action: mask

  - name: sirlar-her-yerde-maskele       # sırlar iç modele bile açık gitmesin
    when: { entity_in: ["SECRET_*"] }
    action: mask

  - name: stajyer-tckn-engel
    when: { teams: [stajyer], destination: external, entity_in: [TCKN] }
    action: block
    mode: monitor                        # önce gözlemle: engellemez, "engellerdi" diye kaydeder
```

Bir isteğin politikadan nasıl geçeceğini görmek için (upstream'e gitmez):

```bash
curl -s localhost:8080/v1/policy/simulate -H 'Authorization: Bearer <yönetici token>' \
  -H 'content-type: application/json' -d '{"model":"gpt-4o","messages":[...]}'
```

## Kurulum (OKD / OpenShift)

Helm chart gateway'i kurar; Kafka ve ClickHouse kurumdaki mevcut kümelerdir
(ClickHouse şeması: `clickhouse/init.sql`, bir kez).

```bash
docker build -f gateway/Dockerfile -t harbor.sirket.local/telveguard/gateway:0.1.0 .

oc create secret generic telveguard-sirlar -n ai-guvenlik \
  --from-literal=admin-token=... --from-literal=upstream-external-key=...

helm upgrade --install telveguard deploy/helm/telveguard-gateway -n ai-guvenlik \
  --set image.repository=harbor.sirket.local/telveguard/gateway \
  --set existingSecret=telveguard-sirlar \
  --set upstream.internalUrl=http://vllm.llm.svc:8000/v1 \
  --set audit.kafkaBootstrap=kafka-bootstrap.kafka.svc:9092 \
  --set clickhouse.url=http://clickhouse.telveguard.svc:8123
```

Chart `restricted-v2` SCC ile uyumludur (root yok, salt okunur dosya sistemi) ve Route ile
gelir; düz Kubernetes'te `route.enabled=false,ingress.enabled=true`. Tüm seçenekler:
`deploy/helm/telveguard-gateway/values.yaml`.

Air-gapped ortamda Türkçe NER ve LLM Guard modelleri için `scripts/mirror_models.sh`
ile modelleri indirip bir PVC'ye koyun, `models.*` değerlerini açın.

## Yapılandırma

| Değişken | Açıklama |
|---|---|
| `UPSTREAM_INTERNAL_URL` / `UPSTREAM_EXTERNAL_URL` | Kurum içi ve yurt dışı LLM adresleri (OpenAI uyumlu) |
| `UPSTREAM_INTERNAL_KEY` / `UPSTREAM_EXTERNAL_KEY` | Upstream API anahtarları |
| `POLICY_PATH` | Politika dosyası |
| `KAFKA_BOOTSTRAP`, `KAFKA_AUDIT_TOPIC` | Denetim kaydı; boşsa olaylar stdout'a yazılır |
| `AUDIT_STORE_MASKED=1` | Maskelenmiş prompt da saklansın (ham prompt hiçbir zaman saklanmaz) |
| `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DB` | Röntgen ve KVKK raporu için (yalnızca okuma yetkili kullanıcı önerilir) |
| `TELVEGUARD_ADMIN_TOKEN` | Yönetim uçları (Röntgen, simülatör, rapor); **boşsa bu uçlar kapalıdır** |
| `ENABLE_TR_NER=1`, `TR_NER_MODEL_PATH` | Türkçe kişi / kurum / yer adı tespiti (BERT, lokal model) |
| `ENABLE_LLM_GUARD=1` | Ek injection sınıflandırıcı (LLM Guard) |

Tahmini maliyet `policies/default.yaml` içindeki `pricing` tablosundan hesaplanır; fiyatı
girilmemiş modeller Röntgen'de "fiyat tanımsız" görünür.

## Yönetim uçları

Hepsi `Authorization: Bearer <TELVEGUARD_ADMIN_TOKEN>` ister.

| Uç | Ne döner |
|---|---|
| `GET /xray` | Röntgen dashboard'u (veri içermez; token'la aşağıdaki API'yi çağırır) |
| `GET /v1/xray?days=30&team=` | Özet, günlük trend, ekip / model / veri türü kırılımı, kural isabetleri |
| `GET /v1/reports/kvkk-transfer?month=2026-09` | KVKK yurt dışı aktarım raporu (CSV; `&format=json` da olur) |
| `POST /v1/policy/simulate` | Bir isteğe verilecek karar ve modele gidecek maskeli mesajlar |

## MCP / agent trafiği (ContextForge)

Agent'ların araç çağrıları IBM ContextForge üzerinden geçiyorsa aynı koruma eklenti olarak eklenir:

```bash
docker build -f contextforge/Containerfile -t telveguard/contextforge:dev .
```

- Araç çıktısındaki kişisel veri ve sırlar maskelenir, gizlenmiş injection engellenir.
- Kurum dışı araçlara (`slack*`, `email*`, `web_*`, `http_*`, `github*`) kişisel veri veya sır
  gönderilmesi engellenir. Ayarlar: `contextforge/plugins-telveguard.yaml`.

## Geliştirme

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r gateway/requirements.txt pytest pytest-asyncio cpex \
    -e packages/telveguard-core -e packages/telveguard-contextforge
pytest -q
```

Uçtan uca testler gerçek Kafka, ClickHouse ve ContextForge'a karşı koşar (ortam yoksa atlanır):

```bash
docker build -f contextforge/Containerfile -t telveguard/contextforge:dev .
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
docker compose -f docker-compose.contextforge.yml up -d
TELVEGUARD_E2E_URL=http://localhost:8080 TELVEGUARD_CF_URL=http://localhost:4444 pytest -q
```

```
gateway/                         LLM gateway + Röntgen dashboard
packages/telveguard-core/        Tespit motoru: Türkçe PII, sırlar, injection, politika (bağımlılıksız)
packages/telveguard-contextforge/ ContextForge eklentisi
contextforge/                    ContextForge imajı + eklenti ayarları
deploy/helm/telveguard-gateway/  OKD / OpenShift Helm chart'ı
clickhouse/init.sql              Denetim şeması
policies/default.yaml            Örnek KVKK politikası + fiyat tablosu
docs/FORK_STRATEGY.md            ContextForge'u neden ve nasıl kullanıyoruz
```

## Kullanılan açık kaynak projeler

Upstream projeler değiştirilmez; eklenti / adaptör olarak sarılır (ayrıntı: `docs/FORK_STRATEGY.md`).

| Proje | Lisans | Rolü |
|---|---|---|
| IBM ContextForge | Apache 2.0 | MCP / agent gateway (Telveguard eklentisiyle) |
| ClickHouse + Kafka | Apache 2.0 | Denetim kaydı ve raporlar |
| BERTurk NER | model kartına bakın | Opsiyonel Türkçe kişi / kurum / yer tespiti |
| LLM Guard | MIT | Opsiyonel injection sınıflandırıcı |
| Microsoft Presidio | MIT | Opsiyonel adaptör (çekirdek Presidio'ya bağımlı değil) |

## Bilinen sınırlar

- Kullanıcı ve ekip bilgisi şimdilik header'dan geliyor; üretimde OIDC / JWT (Keycloak, Entra ID) gerekli.
- Maskeleme gereken streaming istekleri tamponlanıp tek parça döner; maskesiz streaming'de
  model çıktısı taranmaz ve token / maliyet bilgisi gelmez.
- Injection kuralları sezgisel bir başlangıç setidir; Türkçe saldırı veri setiyle eğitilmiş
  bir sınıflandırıcı hedefleniyor. LLM Guard için lokal model yolu henüz bağlanmadı.
- ContextForge'da yer tutucu numaraları (`[TCKN_1]`) tek araç çağrısı içinde tutarlıdır,
  çağrılar arasında değil.

## Yol haritası

1. **Faz 1 (tamamlandı):** LLM gateway, Türkçe PII ve sır tespiti, denetim kaydı, Röntgen,
   KVKK aktarım raporu, politika gözlem modu ve simülatörü, OKD Helm chart'ı.
2. **Faz 2:** MCP gateway'de araç izin listesi ve agent kimliği; gölge AI tespiti için tarayıcı eklentisi.
3. **Faz 3:** AI envanteri, EU AI Act risk sınıflandırması, VERBİS raporları.
