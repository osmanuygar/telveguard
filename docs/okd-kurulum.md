# OKD / OpenShift üretim kurulumu (bastion'dan)

Telveguard gateway'ini Helm ile bir OKD kümesine kurmanın adım adım yolu. Bu belge kurulumu
yapan platform ekibi içindir. Komutlar kümeye erişimi olan bastion sunucusunda çalışır;
geliştirici makinesinden kümeye bağlantı gerekmez.

Kafka, ClickHouse ve Redis bu chart'ın parçası değildir: kurumdaki mevcut kümelere bağlanır.

## 0. Ön koşullar

| Gerekli | Kontrol |
|---|---|
| Bastion'da `oc` ve `helm` (3.8+) | `oc version --client && helm version` |
| Namespace açma ya da mevcut namespace'te `admin` yetkisi | `oc auth can-i create deployments -n <namespace>` |
| İmaj Harbor'da (bkz. [Sürüm yayını](#sürüm-yükseltme)) | Harbor'da `<proje>/telveguard/gateway:<sürüm>` |
| Harbor robot hesabı (pull) | Harbor → proje → Robot Accounts |
| OIDC istemcisi (Keycloak / Entra ID) | issuer, audience, ekip grupları, `telveguard-admin` grubu |
| Kafka kullanıcısı ve topic | `telveguard.audit.v1`, yalnızca gateway yazar |
| ClickHouse yönetici erişimi (şema için bir kez) | `clickhouse-client --query 'SELECT 1'` |
| Redis (birden fazla pod / worker için zorunlu) | `redis-cli -u redis://<redis>:6379 ping` |
| Pod'lardan çıkış: vLLM, Kafka, ClickHouse, Redis, OIDC JWKS; dış sağlayıcı kullanılacaksa `api.openai.com` / `api.anthropic.com` | Egress / proxy kuralları |

## 1. Dosyaları bastion'a taşıyın

Geliştirici makinesinde (depo kökünde) chart'ı paketleyin:

```bash
helm package deploy/helm/telveguard-gateway -d dist/okd
cp deploy/helm/values-okd.example.yaml dist/okd/values-okd.yaml
cp -r clickhouse/init.sql clickhouse/migrations dist/okd/
scp -r dist/okd <kullanici>@<bastion>:~/telveguard-okd
```

Bastion depoya erişebiliyorsa paketlemek yerine `git clone` edip chart dizinini
(`deploy/helm/telveguard-gateway`) doğrudan kullanabilirsiniz.

**Harbor'dan (OCI):** chart Harbor'a konduysa bastion'a yalnızca değer dosyası ve `init.sql` taşınır;
chart ve imajlar Harbor'dan gelir. Kurulum komutlarında `.tgz` yerine OCI adresi verilir:

```bash
# bir kez, chart'ı yayınlayan makinede
helm package deploy/helm/telveguard-gateway
helm push telveguard-gateway-0.7.1.tgz oci://harbor.sirket.local/<proje>/telveguard

# bastion'da (9. adımda .tgz yerine)
helm registry login harbor.sirket.local
helm upgrade --install telveguard oci://harbor.sirket.local/<proje>/telveguard/telveguard-gateway \
  --version 0.7.1 -f values-okd.yaml
```

Chart sürümü imajdan bağımsız patch alabilir (ör. chart 0.7.1, imaj 0.7.0: `appVersion`).

Bundan sonraki adımlar bastion'da, `~/telveguard-okd` dizininde yapılır.

## 2. Kümeye giriş ve namespace

```bash
oc login https://api.<küme>:6443          # kendi kimliğinizle; token'ı paylaşmayın
oc new-project telveguard                  # ya da: oc project <mevcut-namespace>
```

## 3. Harbor pull secret'ı

```bash
oc create secret docker-registry harbor-pull \
  --docker-server=harbor.sirket.local \
  --docker-username='robot$<proje>+telveguard' --docker-password='<robot-token>'
```

Adı `values-okd.yaml` içindeki `imagePullSecrets` ile aynı olmalı.

## 4. Uygulama sırları

Bütün sırlar tek bir Secret'ta durur (`existingSecret: telveguard-sirlar`). Değerleri values
dosyasına yazmayın: Helm release geçmişinde açık metin saklanır.

```bash
oc create secret generic telveguard-sirlar \
  --from-literal=admin-token="$(openssl rand -hex 32)" \
  --from-literal=subject-hash-key="$(openssl rand -hex 32)" \
  --from-literal=metrics-token="$(openssl rand -hex 32)" \
  --from-literal=clickhouse-password='<telveguard_reader şifresi>' \
  --from-literal=kafka-sasl-password='<kafka şifresi>' \
  --from-literal=redis-password='<redis şifresi>' \
  --from-literal=upstream-external-key='<openai anahtarı>' \
  --from-literal=upstream-anthropic-key='<anthropic anahtarı>'
```

| Anahtar | Ne için | Gerekli mi |
|---|---|---|
| `admin-token` | Otomasyon için yönetim uçları (insanlar `telveguard-admin` grubuyla girer) | Önerilir |
| `subject-hash-key` | KVKK ilgili kişi araması (en az 32 karakter) | Önerilir |
| `metrics-token` | `/metrics` (`metrics.requireToken: true`) | Evet (örnek değerlerle) |
| `clickhouse-password` | Röntgen ve raporlar (okuma kullanıcısı) | ClickHouse varsa |
| `kafka-sasl-password` | Denetim kaydı (`SASL_SSL`) | SASL varsa |
| `redis-password` | Kota sayacı, politika onay kilidi | Redis parolalıysa |
| `upstream-*-key` | LLM sağlayıcı anahtarları | Kullanılan sağlayıcılar için |
| `shadow-ai-token` | Tarayıcı eklentisi olayları | Eklenti dağıtılacaksa |
| `guardrail-token` | LiteLLM / agentgateway guardrail | Kullanılıyorsa |
| `contextforge-token` | ContextForge eklentisi kurumsal sözlüğü gateway'den çeker (terimler düz metin gider) | ContextForge kullanılıyorsa |
| `policy-store-password`, `policy-git-token` | Konsoldan politika yönetimi, Bitbucket yansıtma | Sonra (bkz. [bitbucket.md](bitbucket.md)) |

> **`subject-hash-key` sonradan değiştirilmez.** Değişirse eski kayıtlarda ilgili kişi araması
> çalışmaz. Değeri kurum kasasında (Vault vb.) saklayın:
> `oc get secret telveguard-sirlar -o jsonpath='{.data.subject-hash-key}' | base64 -d`

Sonradan anahtar eklemek için:

```bash
oc patch secret telveguard-sirlar -p '{"stringData":{"shadow-ai-token":"'"$(openssl rand -hex 32)"'"}}'
oc rollout restart deploy/telveguard-telveguard-gateway
```

## 5. Kurum içi CA

Kafka (`SSL` / `SASL_SSL`), ClickHouse (`https://`) ya da Bitbucket kurum içi bir CA ile
imzalıysa CA dosyasını ConfigMap olarak verin; örnek değerler bunu `/etc/kurum-ca/ca.pem`
yoluna bağlar (`extraVolumes`, `extraVolumeMounts`):

```bash
oc create configmap kurum-ca --from-file=ca.pem=<kurum-ca.pem>
```

ClickHouse `https://` ise `values-okd.yaml` içine ekleyin:

```yaml
extraEnv:
  - { name: SSL_CERT_FILE, value: /etc/kurum-ca/ca.pem }
```

CA gerekmiyorsa `extraVolumes`, `extraVolumeMounts` ve `audit.kafka.caFile` satırlarını silin.

## 6. ClickHouse şeması (bir kez)

`init.sql` içindeki Kafka tablosu (`audit_queue`) varsayılan olarak `kafka:9092` adresini
okur. Çalıştırmadan önce `kafka_broker_list`'i kurumdaki Kafka adresiyle değiştirin. Kafka
SASL / SSL kullanıyorsa ClickHouse sunucusunun `config.xml`'inde `<kafka>` bölümüne
(`security_protocol`, `sasl_mechanism`, `sasl_username`, `sasl_password`, `ssl_ca_location`)
tüketici ayarları ClickHouse yöneticisi tarafından girilmelidir.

```bash
sed -i "s/'kafka:9092'/'<kafka-bootstrap>:9093'/" init.sql
clickhouse-client --host <clickhouse> --user <yönetici> --multiquery < init.sql
```

Yeni kurulumda `migrations/` gerekmez (`init.sql` hepsini içerir); yalnızca eski bir sürümden
yükseltirken çalıştırılır.

Kullanıcılar (en az yetki):

```sql
CREATE USER IF NOT EXISTS telveguard_reader IDENTIFIED BY '<şifre>';
GRANT SELECT ON telveguard.* TO telveguard_reader;

-- Yalnızca politika deposu açılacaksa (policy.store.enabled)
CREATE USER IF NOT EXISTS telveguard_policy IDENTIFIED BY '<şifre>';
GRANT SELECT, INSERT ON telveguard.policy_versions TO telveguard_policy;
GRANT SELECT, INSERT ON telveguard.policy_events TO telveguard_policy;
```

Denetim kayıtları 2 yıl saklanır (`audit` tablosundaki TTL); kurum saklama süresi farklıysa
`init.sql`'i çalıştırmadan önce değiştirin.

## 7. Kafka

- Topic: `telveguard.audit.v1` (bölüm sayısı pod sayısından az olmasın, ör. 6).
- ACL: gateway kullanıcısı (`audit.kafka.saslUsername`) yalnızca **yazar**; ClickHouse
  tüketici grubu `clickhouse-telveguard-audit` yalnızca **okur**. Başka kimse yazamamalı:
  denetim kaydına sahte olay girmesin.

## 8. Değerler

`values-okd.yaml` içindeki `<...>` alanlarını doldurun. Tüm seçenekler:
`helm show values telveguard-gateway-<sürüm>.tgz`.

| Alan | Not |
|---|---|
| `image.repository`, `image.tag` | Harbor yolu ve sürüm |
| `auth.oidc.*` | `issuer` ve `audience` olmadan kurulum reddedilir. `teamPrefix`: yalnızca bu önekli gruplar ekip sayılır |
| `upstream.*` | Kurum içi vLLM ve dış sağlayıcılar |
| `audit.*` | Kafka adresi ve SASL kullanıcısı |
| `clickhouse.url` | Boşsa Röntgen ve raporlar 503 döner |
| `quota.redisUrl` | `replicaCount` / `workers` 1'den büyükken gerekli |
| `route.host` | Boşsa küme varsayılanı |
| `networkPolicy.allowFromNamespaces` | Gateway'i küme içinden çağıracak namespace'leri ekleyin; router (`openshift-ingress`) örnekte var |
| `streamMode` | `buffer` (varsayılan): streaming cevap taranıp tek parça döner. `incremental`: akarken taranır, ilk token hemen gelir; önce bir ekipte deneyin |
| `resources` | Türkçe NER / LLM Guard açılacaksa bellek sınırı ~2–3 Gi (bkz. `models.*`) |

`auth.mode: header` yalnızca test içindir: istemci kimliği doğrulanmaz, herkes başka bir
kullanıcı ya da ekip gibi davranabilir. Üretimde kullanmayın.

## 9. Kurulum

Önce oluşacak nesneleri gözden geçirin (chart tutarsız değerleri burada reddeder):

```bash
helm upgrade --install telveguard telveguard-gateway-0.7.1.tgz -f values-okd.yaml --dry-run | less
```

Sonra kurun:

```bash
helm upgrade --install telveguard telveguard-gateway-0.7.1.tgz -f values-okd.yaml
oc rollout status deploy/telveguard-telveguard-gateway --timeout=5m
```

Kurulum notlarındaki (`helm get notes telveguard`) **UYARI** satırlarını okuyun: eksik Kafka,
Redis ya da açık kalan `header` modu orada görünür.

## 10. Doğrulama

```bash
HOST=$(oc get route telveguard-telveguard-gateway -o jsonpath='{.spec.host}')
ADMIN=$(oc get secret telveguard-sirlar -o jsonpath='{.data.admin-token}' | base64 -d)
METRICS=$(oc get secret telveguard-sirlar -o jsonpath='{.data.metrics-token}' | base64 -d)

curl -s https://$HOST/healthz                                           # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' https://$HOST/metrics          # 401: token'sız kapalı
curl -s -H "Authorization: Bearer $METRICS" https://$HOST/metrics | head -3
curl -s -H "Authorization: Bearer $ADMIN" https://$HOST/v1/policy/info | head -c 300; echo
```

Uçtan uca (kendi OIDC token'ınızla; `telve login` ya da IdP'den alınan token):

```bash
curl -s https://$HOST/v1/chat/completions -H "Authorization: Bearer <oidc-token>" \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"TC 10000000146 olan müşteriyi özetle"}]}'
```

Kontrol listesi:

- [ ] Yanıt döndü; yurt dışı modele TCKN `[TCKN_1]` olarak gitti (Röntgen → olay ayrıntısı).
- [ ] Olay birkaç saniye içinde Röntgen'de (`https://$HOST/xray`, `telveguard-admin` grubuyla) görünüyor:
      Kafka → ClickHouse hattı çalışıyor.
- [ ] Token'sız istek `401` dönüyor.
- [ ] Prometheus'ta (OKD user workload monitoring) `telveguard_` metrikleri geliyor.
- [ ] Pod logunda Kafka hatası yok: `oc logs deploy/telveguard-telveguard-gateway | grep -c -E 'audit_kafka_(failed|unavailable)'`.

İstemcilerin (SDK, Claude Code, `telve`) adresi: `https://$HOST/v1` (Anthropic biçimi için
`https://$HOST`).

## ContextForge (opsiyonel)

MCP araç trafiği için ContextForge bu chart'ın parçası değildir; imajı
`harbor.sirket.local/<proje>/telveguard/contextforge:<sürüm>` ayrı kurulur. Gateway'le birlikte
kullanılacaksa:

- Kurumsal sözlük: gateway Secret'ına `contextforge-token`, ContextForge'a aynı değer
  `TELVEGUARD_CONTEXTFORGE_TOKEN` olarak verilir; eklentide `dictionary_gateway_url: https://$HOST`.
- Araç çağrıları arası yer tutucu vault'u: `TELVEGUARD_VAULT_REDIS_URL` ve `TELVEGUARD_VAULT_KEY`
  (en az 32 karakter; değişirse eski kayıtlar açılamaz, kasada saklayın). Redis'e ulaşılamazsa araç
  çıktısı engellenir.
- amd64 düğümlerde temel ContextForge imajı x86-64-v3 işlemci ister (AVX2; çok eski düğümlerde açılmaz).

## Sürüm yükseltme

1. Yeni imajı Harbor'a gönderin (linux/amd64):
   `docker buildx build --platform linux/amd64 -f gateway/Dockerfile -t harbor.sirket.local/<proje>/telveguard/gateway:<sürüm> --push .`
2. `CHANGELOG.md`'de aradaki **her** sürümün **Yükseltme notları**'nı okuyun (ör. 0.5.0 → 0.7.0:
   0.6.0 ve 0.7.0); varsa `clickhouse/migrations/` altındaki yeni dosyaları sırayla çalıştırın.
   0.5.0 → 0.7.0 arasında ClickHouse değişikliği yoktur; denetim olayındaki yeni `stream_aborted`
   alanı ClickHouse'a yazılmaz, yalnızca Kafka tüketicilerine (SIEM) gider.
3. Yeni chart paketini bastion'a taşıyın, `image.tag`'i güncelleyin ve aynı `helm upgrade --install`
   komutunu çalıştırın.

Geri almak için:

```bash
helm history telveguard
helm rollback telveguard <revizyon>
```

## Sorun giderme

| Belirti | Olası neden |
|---|---|
| `ImagePullBackOff` | `harbor-pull` secret'ı yok / adı farklı, robot hesabın projede pull yetkisi yok |
| `helm` "auth.mode=jwt için auth.oidc.issuer ..." | `auth.oidc.issuer` / `audience` boş |
| `helm` "quota.redisUrl gerekli" | Politika deposu açık ve birden fazla süreç var |
| Pod `CreateContainerConfigError` | `existingSecret` yok ya da namespace farklı |
| Pod `CrashLoopBackOff`, logda `TELVEGUARD_SUBJECT_HASH_KEY en az 32 karakter` | `subject-hash-key` kısa |
| Route `503` / bağlantı yok | NetworkPolicy router namespace'ine izin vermiyor (`openshift-ingress`) |
| Tüm istekler `401` | Token'ın `aud` değeri `auth.oidc.audience` ile aynı değil ya da pod JWKS adresine çıkamıyor |
| Logda `audit_kafka_failed` / `audit_kafka_unavailable` | Kafka adresi, SASL kullanıcısı / şifresi ya da CA. Gateway çalışmaya devam eder; olaylar pod loguna JSON satırı olarak yazılır, Kafka dönünce `audit_kafka_connected` |
| `/metrics` 503 "metrics token tanımlı değil" | `metrics.requireToken` açık ama Secret'ta `metrics-token` yok |
| Röntgen boş, Kafka'da olay var | ClickHouse `audit_queue` yanlış broker'a bakıyor ya da Kafka SASL ayarı ClickHouse'ta yok (6. adım) |
| Röntgen `503` | `clickhouse.url` boş ya da `clickhouse-password` yanlış |
| İstek `413 request_too_large` | Gövde `maxRequestBytes` sınırını aşıyor (32 MB) |
