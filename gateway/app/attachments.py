"""
Ek tarama: görseller (OCR) ve PDF'ler. Politika dosyasındaki `attachments` bölümü:

    attachments:
      ocr: true                 # Tesseract (tur+eng); kapalıysa görseller taranamaz sayılır
      max_bytes: 20000000       # bundan büyük ek taranamaz sayılır
      max_pages: 30             # PDF sayfa sınırı
      unscannable: alert        # allow | alert | block (yalnızca yurt dışı hedefte)

Bulunan veri türleri metindekilerle birleşir ve AYNI kurallardan geçer. Maskeleme gerekirse:
  * görsel: veri bulunan alan karartılır, üstüne yer tutucu ([TCKN_1]) yazılır; model yer
    tutucuyu cevapta kullanırsa kullanıcıya gerçek değer döner. EXIF (konum vb.) de silinir.
  * PDF / metin dosyası: modele maskeli METNİ gider (görseller ve düzen aktarılmaz).
    Kısmen karartılmış PDF'te metin katmanı altta kalabilir; metne çevirmek sızıntısızdır.

Taranamayan ek: uzak adres ya da file_id (içeriği gateway görmez), şifreli / bozuk PDF,
desteklenmeyen tür, sınırı aşan boyut, OCR kapalıyken görsel. Yurt dışı hedefte `unscannable`
kararı uygulanır ve "ek-taranamadi" kuralı kayda geçer; kurum içi hedefte dokunulmaz.

Claude Code her turda tüm konuşmayı (ekran görüntüleri dahil) yeniden gönderir: tarama sonucu
içerik özetine göre süreç içinde önbelleğe alınır, aynı görsel ikinci kez OCR'lanmaz.
Önbellekte çıkarılan metin (kişisel veri içerebilir) yalnızca bellekte ve sınırlı sayıda durur.
"""
import asyncio
import hashlib
import io
import logging
import os
import shutil
import subprocess
import threading
import time
import warnings
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from telveguard_core.entities import entity_matches
from telveguard_core.policy import SEVERITY

from . import metrics
from .formats import Attachment

log = logging.getLogger("telveguard.attachments")

UNSCANNABLE_ACTIONS = {"allow", "alert", "block"}
UNSCANNABLE_RULE = "ek-taranamadi"
IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp"}
TEXT_TYPES = {"application/json", "application/xml", "application/x-yaml", "application/csv"}
TEXT_EXTS = (".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".log", ".tsv", ".html")
MIN_PAGE_TEXT = 20          # bundan az metin katmanı olan sayfa taranmış sayılır (OCR)
MIN_OCR_SIDE = 24           # daha küçük görseller (ikon) OCR'lanmaz
MAX_PDF_IMAGES = 60         # PDF içi görsel sınırı
MAX_RENDER_SIDE = 3000
CACHE_SIZE = 256
# pdfium thread-safe değildir: PDF'ler (eş zamanlı isteklerde de) sırayla işlenir
_PDFIUM_LOCK = threading.Lock()


class AttachmentConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    ocr: bool = True
    max_bytes: int = 20_000_000
    max_pages: int = 30
    unscannable: str = "alert"
    ocr_langs: str = "tur+eng"
    ocr_timeout_seconds: int = 20

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]]) -> "Settings":
        raw = (cfg or {}).get("attachments") or {}
        if not isinstance(raw, dict):
            raise AttachmentConfigError("attachments bir nesne olmalı")
        unknown = set(raw) - set(cls.__dataclass_fields__)
        if unknown:
            raise AttachmentConfigError(f"attachments: bilinmeyen alan: {', '.join(sorted(unknown))}")
        s = cls(**raw)
        if s.unscannable not in UNSCANNABLE_ACTIONS:
            raise AttachmentConfigError("attachments.unscannable allow, alert ya da block olmalı")
        for name in ("max_bytes", "max_pages", "ocr_timeout_seconds"):
            v = getattr(s, name)
            if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                raise AttachmentConfigError(f"attachments.{name} pozitif bir tamsayı olmalı")
        if not isinstance(s.ocr, bool):
            raise AttachmentConfigError("attachments.ocr true ya da false olmalı")
        return s


# ---------------- OCR ----------------

@dataclass(frozen=True)
class Word:
    text: str
    box: Tuple[int, int, int, int]   # x0, y0, x1, y1 (görsel pikseli)
    line: Tuple[int, ...]            # aynı satırdaki kelimeler aynı anahtar


class TesseractOcr:
    """`tesseract` komut satırı (TSV çıktısı). Python sarmalayıcısı gerekmez."""

    def __init__(self, langs: str = "tur+eng", timeout: int = 20):
        self.cmd = shutil.which("tesseract")
        self.langs, self.timeout = langs, timeout

    @property
    def available(self) -> bool:
        return self.cmd is not None

    def words(self, image) -> List[Word]:
        # Küçük metin (ekran görüntüsü) büyütülünce çok daha iyi okunur
        scale = 2 if max(image.size) < 1500 else 1
        if scale > 1:
            image = image.resize((image.width * scale, image.height * scale))
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        proc = subprocess.run([self.cmd, "stdin", "stdout", "-l", self.langs, "--psm", "3", "tsv"],
                              input=buf.getvalue(), capture_output=True, timeout=self.timeout,
                              env={**os.environ, "OMP_THREAD_LIMIT": "1"}, check=True)
        out: List[Word] = []
        for row in proc.stdout.decode("utf-8", "replace").splitlines()[1:]:
            cols = row.split("\t")
            if len(cols) < 12 or cols[0] != "5" or not cols[11].strip():
                continue
            x, y, w, h = (int(c) // scale for c in cols[6:10])
            out.append(Word(cols[11].strip(), (x, y, x + w, y + h), tuple(int(c) for c in cols[1:5])))
        return out


def words_to_text(words: Sequence[Word]) -> Tuple[str, List[Tuple[int, int]]]:
    """Kelimeleri satır satır metne çevirir; her kelimenin metindeki (başlangıç, bitiş) konumu."""
    parts: List[str] = []
    spans: List[Tuple[int, int]] = []
    pos, prev = 0, None
    for w in words:
        if prev is not None:
            sep = " " if w.line == prev else "\n"
            parts.append(sep)
            pos += 1
        spans.append((pos, pos + len(w.text)))
        parts.append(w.text)
        pos += len(w.text)
        prev = w.line
    return "".join(parts), spans


# ---------------- tarama ----------------

@dataclass
class Scan:
    att: Attachment
    kind: str                        # image | pdf | text | unscannable
    text: str = ""
    reason: str = ""                 # unscannable ise neden
    words: List[Word] = field(default_factory=list)
    spans: List[Tuple[int, int]] = field(default_factory=list)
    pages: int = 0
    redacted: bool = False

    def summary(self) -> Dict[str, Any]:
        return {"name": self.att.name, "role": self.att.role, "media_type": self.att.media_type,
                "kind": self.kind, "reason": self.reason, "pages": self.pages, "chars": len(self.text)}


def _kind_of(att: Attachment) -> str:
    mt, name = att.media_type, att.name.lower()
    data = att.data or b""
    if mt == "application/pdf" or name.endswith(".pdf") or data[:5] == b"%PDF-":
        return "pdf"
    if mt in IMAGE_TYPES or mt.startswith("image/"):
        return "image"
    if mt.startswith("text/") or mt in TEXT_TYPES or name.endswith(TEXT_EXTS):
        return "text"
    return "other"


class AttachmentScanner:
    def __init__(self, settings: Settings, ocr: Optional[Any] = None):
        self.settings = settings
        self.ocr = ocr if ocr is not None else TesseractOcr(settings.ocr_langs, settings.ocr_timeout_seconds)
        if settings.ocr and not self.ocr.available:
            log.warning("ocr_unavailable: tesseract bulunamadı; görseller taranamaz sayılacak")
        self._cache: "OrderedDict[str, Tuple]" = OrderedDict()
        self._sem: Optional[asyncio.Semaphore] = None

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]], ocr: Optional[Any] = None) -> "AttachmentScanner":
        return cls(Settings.from_config(cfg), ocr)

    @property
    def ocr_enabled(self) -> bool:
        return self.settings.ocr and self.ocr.available

    async def scan(self, attachments: List[Attachment]) -> List[Scan]:
        if not attachments:
            return []
        if self._sem is None:
            self._sem = asyncio.Semaphore(max(1, (os.cpu_count() or 2) // 2))
        return list(await asyncio.gather(*(self._scan_one(a) for a in attachments)))

    async def _scan_one(self, att: Attachment) -> Scan:
        kind = _kind_of(att)
        if att.data is None:
            return self._done(Scan(att, "unscannable", reason=att.unscannable_reason), kind)
        if len(att.data) > self.settings.max_bytes:
            return self._done(Scan(att, "unscannable", reason=f"boyut sınırı aşıldı ({len(att.data)} bayt)"), kind)
        key = hashlib.sha256(att.data).hexdigest() + ("o" if self.ocr_enabled else "")
        if key in self._cache:
            self._cache.move_to_end(key)
            kind_, text, reason, words, spans, pages = self._cache[key]
            metrics.ATTACHMENTS.labels(kind, "cached").inc()
            return Scan(att, kind_, text, reason, words, spans, pages)
        t0 = time.perf_counter()
        async with self._sem:
            scan = await asyncio.to_thread(self._scan_sync, att, kind)
        metrics.ATTACHMENT_SCAN_SECONDS.observe(time.perf_counter() - t0)
        self._cache[key] = (scan.kind, scan.text, scan.reason, scan.words, scan.spans, scan.pages)
        if len(self._cache) > CACHE_SIZE:
            self._cache.popitem(last=False)
        return self._done(scan, kind)

    @staticmethod
    def _done(scan: Scan, kind: str) -> Scan:
        metrics.ATTACHMENTS.labels(kind, "unscannable" if scan.kind == "unscannable" else "scanned").inc()
        return scan

    def _scan_sync(self, att: Attachment, kind: str) -> Scan:
        try:
            if kind == "pdf":
                with _PDFIUM_LOCK:
                    return self._pdf(att)
            if kind == "image":
                return self._image(att)
            if kind == "text":
                try:
                    return Scan(att, "text", att.data.decode("utf-8"))
                except UnicodeDecodeError:
                    return Scan(att, "unscannable", reason="metin dosyası UTF-8 değil")
            return Scan(att, "unscannable", reason=f"desteklenmeyen tür ({att.media_type or 'bilinmiyor'})")
        except subprocess.TimeoutExpired:
            return Scan(att, "unscannable", reason="OCR zaman aşımı")
        except Exception as e:  # bozuk / kötü niyetli dosya isteği 500'e çevirmesin
            log.warning("attachment_scan_failed kind=%s error=%s", kind, type(e).__name__)
            return Scan(att, "unscannable", reason=f"okunamadı ({type(e).__name__})")

    def _open_image(self, data: bytes):
        from PIL import Image
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)  # sıkıştırma bombası
            img = Image.open(io.BytesIO(data))
            img.load()
        return img

    def _image(self, att: Attachment) -> Scan:
        if not self.ocr_enabled:
            return Scan(att, "unscannable", reason="OCR kapalı")
        img = self._open_image(att.data)
        if getattr(img, "n_frames", 1) > 1:
            return Scan(att, "unscannable", reason="animasyonlu görsel")
        if min(img.size) < MIN_OCR_SIDE:
            return Scan(att, "image")
        words = self.ocr.words(img.convert("RGB"))
        text, spans = words_to_text(words)
        return Scan(att, "image", text, words=words, spans=spans)

    def _pdf(self, att: Attachment) -> Scan:
        import pypdfium2 as pdfium
        import pypdfium2.raw as pdfium_c
        try:
            pdf = pdfium.PdfDocument(att.data)
        except pdfium.PdfiumError as e:
            reason = "şifreli PDF" if "password" in str(e).lower() else "bozuk PDF"
            return Scan(att, "unscannable", reason=reason)
        try:
            n = len(pdf)
            if n > self.settings.max_pages:
                return Scan(att, "unscannable", reason=f"{n} sayfa (sınır {self.settings.max_pages})", pages=n)
            pages: List[str] = []
            images = 0
            for i in range(n):
                page = pdf[i]
                text = page.get_textpage().get_text_bounded().strip()
                ocr_texts: List[str] = []
                if len(text) < MIN_PAGE_TEXT:
                    # Taranmış sayfa: sayfanın tamamı OCR
                    if not self.ocr_enabled:
                        if next(page.get_objects(filter=[pdfium_c.FPDF_PAGEOBJ_IMAGE], max_depth=2), None):
                            return Scan(att, "unscannable", reason="taranmış PDF (OCR kapalı)", pages=n)
                    else:
                        w, h = page.get_size()
                        scale = min(2.0, MAX_RENDER_SIDE / max(w, h, 1))
                        ocr_texts.append(words_to_text(self.ocr.words(
                            page.render(scale=scale).to_pil().convert("RGB")))[0])
                else:
                    # Metinli sayfadaki görseller (ör. belgeye gömülü kimlik fotoğrafı)
                    for obj in page.get_objects(filter=[pdfium_c.FPDF_PAGEOBJ_IMAGE], max_depth=2):
                        if not self.ocr_enabled:
                            return Scan(att, "unscannable", reason="görsel içeren PDF (OCR kapalı)", pages=n)
                        images += 1
                        if images > MAX_PDF_IMAGES:
                            return Scan(att, "unscannable", reason="PDF'te çok fazla görsel", pages=n)
                        img = obj.get_bitmap(render=False).to_pil()
                        if min(img.size) >= MIN_OCR_SIDE:
                            ocr_texts.append(words_to_text(self.ocr.words(img.convert("RGB")))[0])
                pages.append("\n".join(t for t in [text, *ocr_texts] if t))
            body = "\n\n".join(f"--- Sayfa {i + 1} ---\n{t}" for i, t in enumerate(pages)) if n > 1 else \
                (pages[0] if pages else "")
            return Scan(att, "pdf", body, pages=n)
        finally:
            pdf.close()

    # ---------------- karar ve maskeleme ----------------

    def apply_unscannable(self, decision, scans: List[Scan], destination: str) -> None:
        """Yurt dışı hedefte taranamayan ek: politika kararını sıkılaştırır (gevşetmez)."""
        unscanned = [s for s in scans if s.kind == "unscannable"]
        action = self.settings.unscannable
        if not unscanned or destination != "external" or action == "allow":
            return
        decision.rules.append(UNSCANNABLE_RULE)
        reasons = ", ".join(sorted({f"{s.att.name}: {s.reason}" for s in unscanned}))
        if SEVERITY[action] > SEVERITY[decision.action]:
            decision.action = action
            decision.reason = (f"Taranamayan ek yurt dışı modele gönderilemez ({reasons})."
                               if action == "block" else f"Taranamayan ek ({reasons})")
        if SEVERITY[action] > SEVERITY[decision.would_action]:
            decision.would_action = action

    def mask(self, pii, scans: List[Scan], mask_entities, vault: Dict[str, str]) -> List[str]:
        """Maskelenecek veri içeren ekleri değiştirir; denetim için kısa açıklamalar döner."""
        notes: List[str] = []
        for s in scans:
            if s.kind == "unscannable" or not s.text:
                continue
            findings = [f for f in pii.analyze(s.text) if entity_matches(f.entity, list(mask_entities))]
            if not findings:
                continue
            masked = pii.mask(s.text, list(mask_entities), vault).text
            if s.kind == "image":
                try:
                    data, media_type = self._redact_image(s, findings, vault)
                    s.att.set_image(data, media_type)
                    s.redacted = True
                    notes.append(f"[{s.att.name}: {len(findings)} alan karartıldı]\n{masked}")
                    metrics.ATTACHMENTS.labels("image", "redacted").inc()
                    continue
                except NotImplementedError:
                    pass  # dosya alanındaki görsel: metne çevrilir
            label = {"pdf": "PDF belgesinin", "image": "görselin", "text": "dosyanın"}[s.kind]
            s.att.set_text(f"[{s.att.name}: {label} metni. Telveguard kişisel verileri maskeledi; "
                           f"görseller ve sayfa düzeni aktarılmadı.]\n\n{masked}")
            s.redacted = True
            notes.append(f"[{s.att.name}: maskeli metne çevrildi]\n{masked}")
            metrics.ATTACHMENTS.labels(s.kind, "redacted").inc()
        return notes

    def _redact_image(self, s: Scan, findings, vault: Dict[str, str]) -> Tuple[bytes, str]:
        from PIL import ImageDraw, ImageFont
        img = self._open_image(s.att.data)
        fmt = "JPEG" if img.format == "JPEG" else "PNG"
        img = img.convert("RGB")
        draw = ImageDraw.Draw(img)
        reverse = {v: k for k, v in vault.items()}
        for f in findings:
            placeholder = reverse.get(s.text[f.start:f.end], "")
            boxes: Dict[Tuple[int, ...], List[int]] = {}
            for w, (ws, we) in zip(s.words, s.spans):
                if ws < f.end and we > f.start:
                    b = boxes.setdefault(w.line, [*w.box])
                    b[0], b[1] = min(b[0], w.box[0]), min(b[1], w.box[1])
                    b[2], b[3] = max(b[2], w.box[2]), max(b[3], w.box[3])
            for x0, y0, x1, y1 in boxes.values():
                draw.rectangle((x0 - 3, y0 - 3, x1 + 3, y1 + 3), fill="black")
                if placeholder:
                    size = max(8, min(int((y1 - y0) * 0.8), 40))
                    draw.text((x0, y0), placeholder, fill="white", font=ImageFont.load_default(size=size))
        buf = io.BytesIO()
        img.save(buf, format=fmt, **({"quality": 90} if fmt == "JPEG" else {}))  # EXIF taşınmaz
        return buf.getvalue(), f"image/{fmt.lower()}"


def load(policy_path: str) -> AttachmentScanner:
    import yaml

    with open(policy_path, encoding="utf-8") as f:
        return AttachmentScanner.from_config(yaml.safe_load(f))
