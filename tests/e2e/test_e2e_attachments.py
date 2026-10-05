"""Uçtan uca ek tarama: gateway imajındaki gerçek Tesseract ve pdfium ile (compose ortamı)."""
import base64
import io
import json
import os

import httpx
import pytest

pytest.importorskip("PIL")
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

from tests.test_attachments import make_pdf  # noqa: E402
from tests.test_tr_pii import make_tckn  # noqa: E402

GATEWAY = os.getenv("TELVEGUARD_E2E_URL")
pytestmark = pytest.mark.skipif(not GATEWAY, reason="TELVEGUARD_E2E_URL verilmedi")
TCKN = make_tckn(7)


def chat(content, model="gpt-4o"):
    return httpx.post(f"{GATEWAY}/v1/chat/completions", timeout=60, headers={"x-telveguard-team": "e2e-ek"},
                      json={"model": model, "messages": [{"role": "user", "content": content}]})


def kimlik_png() -> bytes:
    img = Image.new("RGB", (1000, 200), "white")
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=44)
    d.text((30, 30), f"TC Kimlik No: {TCKN}", fill="black", font=font)
    d.text((30, 110), "Ad Soyad: Deneme Kisi", fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_image_tckn_redacted_by_real_ocr():
    data = kimlik_png()
    r = chat([{"type": "text", "text": "Bu kimliği özetle"},
              {"type": "image_url", "image_url": {"url": "data:image/png;base64," + base64.b64encode(data).decode()}}])
    assert r.status_code == 200, r.text
    sent = r.json()["mock_received_messages"][-1][1]["image_url"]["url"]
    img = Image.open(io.BytesIO(base64.b64decode(sent.split(",", 1)[1]))).convert("L")
    # TCKN'nin yazdığı bölge (yer tutucu yazısının sağı) siyah; ikinci satır duruyor
    region = [img.getpixel((x, y)) for x in range(460, 560, 4) for y in range(48, 72, 4)]
    assert sum(p < 30 for p in region) > len(region) * 0.9
    assert img.getpixel((20, 130)) > 200


def test_pdf_masked_as_text():
    pdf = make_pdf([f"Musteri TCKN: {TCKN}"])
    r = chat([{"type": "file", "file": {"filename": "sozlesme.pdf",
                                        "file_data": "data:application/pdf;base64," + base64.b64encode(pdf).decode()}}])
    assert r.status_code == 200, r.text
    received = json.dumps(r.json()["mock_received_messages"], ensure_ascii=False)
    assert TCKN not in received and "[TCKN_1]" in received


def test_remote_image_flagged():
    r = chat([{"type": "image_url", "image_url": {"url": "https://ornek.com/kimlik.png"}}])
    assert r.status_code == 200          # varsayılan politika: alert
