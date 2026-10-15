# telveguard-agent

[Telveguard](https://github.com/osmanuygar/telveguard) için kod asistanı ajanı (`telve`):
Cursor ve Claude Code'u kurum politikasına bağlar. Kontrol makinede, veri makineden çıkmadan önce yapılır.

```bash
pip install telveguard-agent
telve setup --gateway https://telveguard.sirket.local
telve login                     # kurum hesabı (OIDC cihaz akışı)
telve install cursor
telve install claude --route
telve doctor
```

| | Cursor | Claude Code |
|---|---|---|
| Prompt | kişisel veri / sır / injection varsa durdurulur | durdurulur; `--route` ile yolda maskelenir |
| Okunan dosya, Tab | durdurulur | çıktı maskelenir |
| Komut, MCP, web araçları | durdurulur | durdurulur |
| Araç çıktısı | — (MCP için ContextForge) | maskelenir |

Karar gateway'deki politikayla verilir ve denetim kaydına (Röntgen, POC raporu) yazılır; metnin kendisi saklanmaz.
Gateway'e ulaşılamazsa `fail_closed: true` durdurur, aksi hâlde yerel tarama yapılır.

Kurumsal dağıtım (MDM): `/Library/Application Support/Telveguard/agent.json` (Linux `/etc/telveguard/`,
Windows `C:\ProgramData\Telveguard\`) ve `telve install ... --scope enterprise --print` çıktısı.
Ayrıntı: [README](https://github.com/osmanuygar/telveguard#kod-asistanları-cursor-ve-claude-code).

Lisans: Apache-2.0
