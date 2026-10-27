# Politika sürümlerini Bitbucket Data Center'a yansıtma

Telveguard konsolunda (Politika sekmesi) yayına alınan her politika sürümü — onay, acil yayın,
geri alma — kurumun Bitbucket Data Center deposuna da yazılır. Kim yazdı, kim yayına aldı ve
gerekçe commit mesajındadır. Bu belge Bitbucket yöneticisi ve Telveguard'ı kuran ekip içindir.

Ön koşul: konsoldan politika yönetimi açık olmalı (`POLICY_STORE=clickhouse`, Helm
`policy.store.enabled: true`).

## 1. Bitbucket tarafı

### Depo

Politikanın duracağı depo, ör. proje `SEC`, depo `telveguard-config`. Dosya
(`policies/policy.yaml`) ilk yayında Telveguard tarafından oluşturulur; hedef dalın (ör. `main`)
var olması yeterlidir.

### Erişim token'ı

Depo ayarları → **HTTP access tokens** → **Create token**:

- Yetki: **Repository write** (okuma yetmez).
- Bitiş tarihi koyun; yenilerken yalnızca Telveguard Secret'ını güncellemek yeterli.
- Kişisel token yerine depo (ya da proje) token'ı önerilir: çalışan ayrılınca bağlantı kopmaz.
- Commit'in yazarı token'ın kimliği görünür; asıl kişiler (yazan, yayına alan) commit mesajındadır.

### Dal izinleri → yöntem

Depo ayarları → **Branch permissions**:

| Hedef dalda | Telveguard ayarı | Ne olur |
|---|---|---|
| Doğrudan commit serbest | `mode: commit` | Her sürüm hedef dala commit edilir |
| PR zorunlu (bankalarda yaygın) | `mode: pull_request` | Her sürüm için `telveguard/politika-v<n>` dalı ve PR açılır; gözden geçirenler `reviewers` ile |

PR modunda canlı politika PR'ın merge edilmesini beklemez: konsolda onaylanan sürüm hemen
geçerlidir. PR, Git kaydı ve depodan dağıtılan ConfigMap'in güncellenmesi içindir.

### Ağ

Gateway pod'ları Bitbucket'a HTTPS ile erişebilmeli (NetworkPolicy egress ya da kurum proxy'si;
`HTTPS_PROXY` ortam değişkeni dikkate alınır). Bitbucket kurum içi bir CA ile imzalıysa CA
dosyası `caFile` ile verilir. Düz `http://` adres varsayılan olarak reddedilir (token her istekte gider).

## 2. Telveguard tarafı (OKD / OpenShift)

Token'ı Secret'a koyun:

```bash
oc -n telveguard create secret generic tg-sirlar \
  --from-literal=policy-git-token='<bitbucket token>' \
  --from-literal=policy-store-password='<clickhouse politika kullanıcısının şifresi>'
```

Helm values:

```yaml
existingSecret: tg-sirlar

clickhouse:
  url: http://clickhouse.telveguard.svc:8123

quota:
  redisUrl: redis://redis.telveguard.svc:6379/0   # birden fazla pod varsa (onay kilidi)

policy:
  store:
    enabled: true
    git:
      enabled: true
      url: https://bitbucket.sirket.local          # bağlam yolu varsa dahil: .../bitbucket
      webUrl: ""                                   # konsoldaki bağlantılar için, API adresinden farklıysa
      project: SEC                                 # kişisel depo: ~kullanici
      repo: telveguard-config
      branch: main
      path: policies/policy.yaml
      mode: pull_request                           # hedef dal korumalı değilse: commit
      reviewers: [guvenlik.lead, uyum.birimi]      # yalnızca pull_request
      content: full                                # full: dağıtılabilir tam politika | rules: yalnızca kurallar
      strict: false                                # true: Git'e yazılamazsa yayına alınmaz
      message: ""                                  # commit mesajı şablonu; boşsa varsayılan
      caFile: /etc/pki/kurum/ca.pem                # kurum içi CA ise (volume ile bağlayın)
```

```bash
helm upgrade telveguard deploy/helm/telveguard-gateway -n telveguard -f values-prod.yaml
```

Eksik ya da hatalı ayarda Helm kurulumu reddeder; pod açılmazsa logda tüm eksikler tek satırda yazar.

### Seçimler

- **`strict`** — `false` (varsayılan): Bitbucket'a ulaşılamasa da onaylanan sürüm yayına girer;
  yazma arka planda birkaç kez denenir, olmazsa konsolda "yazılamadı" ve "yeniden yaz" çıkar.
  `true`: "Git kaydı olmadan değişiklik olmaz"; Bitbucket kapalıyken acil kural değişikliği de yapılamaz.
- **`content`** — `full`: ConfigMap politikasının tamamı; yalnızca değişen kural satırları yerinde
  değişir, diğer bölümler ve yorumlar korunur. Depodan doğrudan dağıtılabilir (GitOps).
  `rules`: yalnızca kural bölümleri.
- **`message`** — şablon alanları: `{version}` `{event}` `{event_text}` `{author}` `{actor}`
  `{actor_note}` `{comment}` `{note}`. Alanlar tek satıra indirgenir.

Varsayılan commit mesajı:

```
Telveguard politika sürüm 3: BDDK bulgusu: finans TCKN engeli (SOME-1182)

Sürüm 3 onaylandı.
Yazan: ayse.yilmaz
Yayına alan: mehmet.kaya
Not: Etki analizi uygun

Telveguard-Policy-Version: 3
Telveguard-Event: approved
```

### GitOps

ConfigMap'i bu depodan dağıtıyorsanız (ör. ArgoCD) `content: full` ile depodaki dosya her zaman
dağıtılabilir tam politikadır. Helm'de `policy.existingConfigMap` ile ArgoCD'nin oluşturduğu
ConfigMap'i gösterin: depo, ConfigMap ve canlı politika aynı kalır.

## 3. Deneme

1. Konsol → **Politika**. Üstte "Bitbucket · SEC/telveguard-config · main · policies/policy.yaml" görünür.
2. **Bağlantıyı dene** (yazmaz):
   - "✓ erişildi" — hazır ("dosya yok" normal; ilk yayında oluşur).
   - "yetki hatası" — token'ın yetkisi Repository write değil.
   - "dalı bulunamadı" — `branch` yanlış.
   - "Depo bulunamadı" — `project` / `repo` yanlış.
3. Küçük bir değişikliği onaya gönderin, başka bir yöneticiyle onaylayın. Sürüm tablosunun "Git"
   sütununda commit ya da PR bağlantısı görünür.

## Davranış ve güvenlik

- Daha yeni bir sürüm yayına girdiyse eski sürüm depoya hiçbir zaman yazılmaz (yeniden deneme dahil).
- Dosyayı arada başka biri değiştirdiyse güncel commit'le bir kez daha denenir.
- Token konsola, API cevaplarına ve loglara çıkmaz.
- Politika değişikliği OIDC yönetici grubuyla yapılır; statik yönetici token'ı (OIDC varken)
  yalnızca okuma içindir, böylece commit mesajındaki kişiler doğrulanmış kimliklerdir.
