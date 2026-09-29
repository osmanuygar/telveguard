"""
README akış diyagramı: açık ve koyu tema için iki SVG üretir.
GitHub README'de SVG <img> ile gösterilir; sayfa rengini devralamaz, bu yüzden <picture> ile
temaya göre dosya seçilir.   python docs/assets/make_diagram.py
"""
from pathlib import Path

W, H = 1010, 380
THEMES = {
    "light": dict(fg="#1f2328", muted="#59636e", box="#f6f8fa", line="#d0d7de", accent="#8a4b1f",
                  accent_bg="#fbf3ec"),
    "dark": dict(fg="#e6edf3", muted="#9198a1", box="#161b22", line="#3d444d", accent="#e0a871",
                 accent_bg="#2a1d12"),
}
FONT = 'font-family="-apple-system, Segoe UI, Helvetica, Arial, sans-serif"'


def box(c, x, y, w, h, title, sub, accent=False):
    stroke = c["accent"] if accent else c["line"]
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{c["box"]}" stroke="{stroke}"/>'
            f'<text x="{x + 14}" y="{y + 23}" font-size="14" font-weight="600" fill="{c["fg"]}">{title}</text>'
            f'<text x="{x + 14}" y="{y + 42}" font-size="12" fill="{c["muted"]}">{sub}</text>')


def arrow(c, x1, y1, x2, y2, color=None, dashed=False, label=None, lx=None, ly=None, anchor="middle"):
    color = color or c["muted"]
    mid = "acc" if color == c["accent"] else "dim"
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    out = (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1.6"{dash} '
           f'marker-end="url(#{mid})"/>')
    if label:
        out += (f'<text x="{lx}" y="{ly}" font-size="11.5" text-anchor="{anchor}" '
                f'fill="{c["accent"] if color == c["accent"] else c["muted"]}">{label}</text>')
    return out


def render(c):
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" {FONT} '
         'role="img" aria-label="Telveguard istek akışı: kaynaklardan gelen istek kimlik, tarama, politika ve '
         'maskeleme adımlarından geçer; kurum içi modele olduğu gibi, yurt dışı modele maskeli gider; her istek '
         've tarayıcı eklentisi olayları denetim kaydına ve raporlara düşer.">',
         '<defs>']
    for mid, col in (("dim", c["muted"]), ("acc", c["accent"])):
        p.append(f'<marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                 f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{col}"/></marker>')
    p.append('</defs>')

    # Kaynaklar
    for y, t, s in ((30, "Uygulamalar", "OpenAI · Anthropic SDK"), (96, "Kod asistanları", "Claude Code · Codex CLI"),
                    (162, "AI agent'lar", "MCP · ContextForge")):
        p.append(box(c, 20, y, 190, 52, t, s))
        p.append(arrow(c, 210, y + 26, 268, y + 26))

    # Telveguard
    p.append(f'<rect x="270" y="20" width="420" height="200" rx="14" fill="{c["accent_bg"]}" '
             f'stroke="{c["accent"]}" stroke-width="2"/>')
    p.append(f'<text x="290" y="50" font-size="18" font-weight="700" fill="{c["accent"]}">Telveguard</text>')
    p.append(f'<text x="290" y="70" font-size="12" fill="{c["muted"]}">OpenAI ve Anthropic uyumlu · '
             f'uygulama kodu değişmez</text>')
    steps = (("Kimlik", "OIDC · JWT"), ("Tarama", "PII · sır · saldırı"), ("Politika", "kural · kota"),
             ("Maskeleme", "TC → [TCKN_1]"))
    for i, (t, s) in enumerate(steps):
        x = 286 + i * 100
        p.append(f'<rect x="{x}" y="88" width="90" height="52" rx="8" fill="{c["box"]}" stroke="{c["line"]}"/>')
        p.append(f'<text x="{x + 45}" y="110" font-size="13" font-weight="600" text-anchor="middle" '
                 f'fill="{c["fg"]}">{t}</text>')
        p.append(f'<text x="{x + 45}" y="127" font-size="10.5" text-anchor="middle" fill="{c["muted"]}">{s}</text>')
        if i < 3:
            p.append(arrow(c, x + 91, 114, x + 99, 114))
    p.append(f'<text x="290" y="172" font-size="12" fill="{c["fg"]}">↩ Cevap: yer tutucular gerçek değere çevrilir</text>')
    p.append(f'<text x="290" y="192" font-size="12" fill="{c["fg"]}">⛨ Modelin ürettiği yeni kişisel veri / sır gizlenir</text>')

    # Hedefler
    p.append(box(c, 810, 40, 180, 56, "Kurum içi LLM", "vLLM · Ollama"))
    p.append(arrow(c, 690, 68, 808, 68, label="olduğu gibi", lx=749, ly=60))
    p.append(box(c, 810, 150, 180, 56, "Yurt dışı LLM", "OpenAI · Anthropic · Gemini", accent=True))
    p.append(arrow(c, 690, 178, 808, 178, color=c["accent"], label="maskeli · [TCKN_1]", lx=749, ly=170))

    # Denetim ve raporlar
    p.append(arrow(c, 400, 220, 400, 298, label="her istek · ham prompt yok", lx=410, ly=264, anchor="start"))
    p.append(box(c, 300, 300, 200, 56, "Denetim kaydı", "Kafka → ClickHouse"))
    p.append(arrow(c, 500, 328, 578, 328, label="raporlar", lx=539, ly=320))
    p.append(box(c, 580, 300, 410, 56, "Röntgen · KVKK · VERBİS · EU AI Act", "kim, hangi modeli, hangi veriyle kullanıyor"))

    # Gölge AI
    p.append(box(c, 20, 300, 190, 56, "Tarayıcı eklentisi", "ChatGPT'ye yapıştırma"))
    p.append(arrow(c, 210, 328, 298, 328, dashed=True, label="olay, metin yok", lx=254, ly=320))

    p.append('</svg>')
    return "".join(p)


if __name__ == "__main__":
    out = Path(__file__).parent
    for name, colors in THEMES.items():
        (out / f"telveguard-flow-{name}.svg").write_text(render(colors), encoding="utf-8")
        print("yazıldı:", out / f"telveguard-flow-{name}.svg")
