# Fork stratejisi: neden IBM ContextForge, nasıl fork'luyoruz

## Temel seçimi

| Aday | Artı | Eksi | Karar |
|---|---|---|---|
| **IBM ContextForge** | Apache-2.0, Python/FastAPI, MCP + A2A + REST gateway, eklenti sistemi (cpex), RBAC, takımlar, SSO/Keycloak, vault, SIEM, compliance router, Helm chart, OpenShift uyumlu (UID 10001) | Büyük ve hızlı değişen kod tabanı; LLM proxy yolunda eklenti hook'u yok | **Temel** |
| LiteLLM | Çok popüler, LLM yönlendirmede en olgun | 2026'da PyPI tedarik zinciri saldırısı, custom-guardrail RCE CVE'leri, guardrail loglarında secret sızıntısı; enterprise özellikleri ayrı lisans | Arkada yönlendirici olarak opsiyonel, temel değil |
| Bifrost | Çok düşük gecikme | Go; ekip Python ağırlıklı | Hayır |
| Trylon / Occludra | Küçük, anlaşılır | Topluluk küçük, governance yok | Fikir kaynağı |

## "Yumuşak fork" kuralları

1. **Çekirdeğe dokunma.** Telveguard mantığı `telveguard-core` + `telveguard-contextforge` paketlerinde yaşar,
   ContextForge'a eklenti (`kind: telveguard_contextforge.TelveguardPlugin`) olarak takılır.
2. **Dağıtım = upstream imaj + eklenti** (`contextforge/Containerfile`). Upstream sürüm yükseltmek tek satır.
3. **Çekirdek değişikliği zorunluysa:** `telveguard/main` dalında küçük commit + aynı değişiklik upstream'e PR.
   Merge olunca bizim dalda kaldırılır. Hedef: fork'taki fark her zaman birkaç commit.

## Upstream'e önerilecek değişiklikler (bilinen boşluklar)

- **LLM proxy hook'ları:** `llm_proxy_service` yolunda `invoke_hook` çağrısı yok; eklentiler sadece
  tool/prompt/resource/A2A trafiğini görüyor. `llm_pre_invoke` / `llm_post_invoke` hook'u önerilecek.
  Bu gelene kadar sohbet (chat completions) trafiği için Telveguard LLM Gateway'i (`gateway/`) kullanılır.
- **Compliance çerçeveleri:** `ComplianceFramework` şu an FedRAMP, HIPAA, SOC2. KVKK ve EU AI Act eklenecek.

## Telveguard'ın katma değeri (fork'un üstüne)

- Türkçe PII (checksum'lı TCKN/VKN/IBAN/kart, GSM, plaka) — bağımlılıksız, ~0,4 ms/istek
- Yön-farkındalıklı MCP koruması: araca giderken sızdırma engeli, araçtan dönerken maskeleme
- Türkçe prompt injection tespiti (dolaylı injection dahil)
- Kafka + ClickHouse audit ve KVKK raporlama
