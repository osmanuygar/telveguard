# telveguard-contextforge

[Telveguard](https://github.com/osmanuygar/telveguard) için IBM ContextForge eklentisi:
MCP / agent trafiğinde Türkçe kişisel veri, sır ve prompt injection koruması.

```bash
pip install telveguard-contextforge
```

- **Araç çıktısı:** kişisel veri ve sırlar maskelenir; çıktıya gizlenmiş injection engellenir.
- **Araç çağrısı:** kurum dışı araçlara (`slack*`, `email*`, `web_*`, `http_*`, `github*`) kişisel
  veri veya sır gönderilmesi engellenir. ContextForge'un önekli araç adları (`gw-email-send`) da tanınır.
- **Prompt argümanları:** maskelenir, injection engellenir.

ContextForge eklenti yapılandırması:

```yaml
plugins:
  - name: "TelveguardPlugin"
    kind: "telveguard_contextforge.TelveguardPlugin"
    hooks: ["prompt_pre_fetch", "tool_pre_invoke", "tool_post_invoke"]
    mode: "enforce"
    priority: 10
```

Tüm seçenekler: [plugins-telveguard.yaml](https://github.com/osmanuygar/telveguard/blob/main/contextforge/plugins-telveguard.yaml)

Lisans: Apache-2.0
