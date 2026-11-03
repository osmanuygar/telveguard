/*
 * AI sohbet sitelerinde yapıştırma ve gönderim koruması.
 * Metin YEREL olarak taranır (detectors.js); kişisel veri ya da sır varsa:
 *   yapıştırma: warn  -> "Maskeleyerek yapıştır" (önerilen) / "Vazgeç" / "Yine de yapıştır"
 *               block -> yapıştırma engellenir
 *   gönderim (Enter ya da gönder düğmesi; elle yazılan metin de):
 *               warn  -> "Maskele ve gönder" (önerilen) / "Düzenle" / "Yine de gönder"
 *               block -> gönderilmez; "Metni maskele" ile düzeltilip tekrar gönderilebilir
 *   dosya (sürükle-bırak, dosya seçme, dosya yapıştırma): metin dosyaları okunup taranır
 *               warn  -> "Maskeleyerek ekle" (dosyanın maskeli kopyası) / "Vazgeç" / "Yine de ekle"
 *               block -> eklenmez
 *               PDF / görsel / Office taranamaz: unscannableFiles = allow (varsayılan) | block
 * Kurumsal sözlük (proje adları, müşteri unvanları...) servis çalışanının gateway'den çektiği
 * özet listeyle aranır (chrome.storage.local; detectors.js setDictionary).
 * Onaylı araca yönlendirme (MDM: sanctionedAiUrl): pencerelerde "<ad> ile devam et" metni panoya
 * kopyalayıp kurumun onaylı AI aracını açar; sitede bir kez bilgilendirme bandı gösterilir.
 * "Yine de" seçilince gerekçe sorulur (MDM: requireJustification); seçim olaya yazılır, metin yazılmaz.
 * Telveguard'a yalnızca site, veri türü adetleri ve karar gider; metin asla gönderilmez.
 * Pencere closed Shadow DOM'da: sitenin CSS'i bozamaz. Bu bir gizlilik sınırı DEĞİLDİR (window.find ve
 * seçim içine ulaşır): pencerede yalnızca tür ve adet durur, değerler eklenti kökenli çerçevede (preview.js).
 * Maskeli önizleme: çerçeve yakalanan değerleri ve metnin maskeli halini gösterir (sırların yalnızca başı).
 * Çerçeve sitede yüklenemezse pencere yalnızca tür ve adetle çalışır; hepsi maskelenir.
 * Uyar modunda yapıştırma ve gönderimde kullanıcı hassas olmayan değerin işaretini kaldırabilir; bu seçim
 * "yanlış alarm" gerekçesiyle kayda yazılır (adet ve tür; değer yazılmaz).
 * Yerel geri açma (MDM: revealPlaceholders): sayfadaki [TCKN_1] üzerine gelince değer çerçevedeki ipucunda
 * görünür. "Aslıyla kopyala" varsayılan kapalı (MDM: revealCopy): pano siteye açık olabilir. Eşleme yalnızca
 * bu betiğin belleğinde durur; sitenin DOM'una yazılmaz, saklanmaz, gönderilmez. Numaralar sayfa boyunca ortaktır.
 */
(function () {
  "use strict";
  const D = self.TelveguardDetectors;
  if (!D || window.__telveguardLoaded) return;
  window.__telveguardLoaded = true;

  const site = location.hostname.replace(/^www\./, "");
  // Yapılandırma gelene kadar en sıkı hali: servis çalışanı saniyeler içinde uyanabilir, block kurumunda
  // o arada "Yine de" çıkmasın. Normalde saklanan yapılandırma ilk milisaniyelerde bunun yerine geçer.
  let config = { mode: "block", reportVisits: false, unscannableFiles: "block", requireJustification: true,
                 sanctionedAiUrl: "", sanctionedAiName: "", showBanner: true, revealPlaceholders: true, revealCopy: false };
  const hasRuntime = typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage;

  let liveConfig = false;   // servis çalışanının cevabı geldiyse saklanan kayıt onu ezmesin
  let frameFailed = false;  // önizleme çerçevesi bu sayfada açılamadı (sitenin CSP'si)

  function send(event) {
    if (!hasRuntime) return;
    // Çerçeve bu sitede açılamadıysa olaylarda işaretlenir (yalnızca bayrak): konsoldan görülebilsin
    const flag = frameFailed ? { preview_unavailable: true } : {};
    try { chrome.runtime.sendMessage({ type: "event", event: { site, ...event, ...flag } }); } catch { /* eklenti yenilendi */ }
  }

  if (hasRuntime) {
    try {
      chrome.runtime.sendMessage({ type: "getConfig" }, (c) => {
        if (c) { config = c; liveConfig = true; }
        setTimeout(showBanner, 0);   // yapılandırma eşzamanlı gelse de betiğin tamamı yüklendikten sonra
        if (config.reportVisits && !sessionStorage.getItem("telveguard-visit")) {
          try { sessionStorage.setItem("telveguard-visit", "1"); } catch { /* yok say */ }
          send({ action: "visit" });
        }
      });
    } catch { /* varsayılan yapılandırma */ }
  }

  const DICT_KEY = "telveguardDictionary", CONFIG_KEY = "telveguardConfig";
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    try {
      chrome.storage.local.get([DICT_KEY, CONFIG_KEY], (v) => {
        D.setDictionary(v && v[DICT_KEY]);
        if (v && v[CONFIG_KEY] && !liveConfig) config = v[CONFIG_KEY];
      });
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "local") return;
        if (changes[DICT_KEY]) D.setDictionary(changes[DICT_KEY].newValue);
        // Kayıt içerik betiği bağlamından yazılabilir (DevTools): değeri değil, servis çalışanının cevabını al
        if (changes[CONFIG_KEY] && hasRuntime) chrome.runtime.sendMessage({ type: "getConfig" }, (c) => {
          if (!c) return;
          config = c;
          if (pageVault) remember(pageVault);   // geri açma sonradan açıldıysa başlasın
        });
      });
    } catch { /* sözlüksüz devam */ }
  }

  // Kullanıcının "yine de" dediği değerler (yalnızca bu sayfanın belleğinde; saklanmaz / gönderilmez):
  // aynı değer için gönderimde ikinci kez sorulmaz
  const allowedValues = new Set();
  const allow = (text, findings) => findings.forEach((f) => allowedValues.add(text.slice(f.start, f.end)));

  function counts(findings, c = {}) {
    for (const f of findings) c[f.entity] = (c[f.entity] || 0) + 1;
    return c;
  }
  const describe = (c) => Object.entries(c).map(([e, n]) => `${D.label(e)}${n > 1 ? ` (${n})` : ""}`);

  // ---------- onaylı araca yönlendirme ----------
  const sanctionedName = () => config.sanctionedAiName || "Kurum AI asistanı";
  function openSanctioned(text) {
    // Metin adres satırına konmaz (kişisel veri URL'de olmasın): panoya kopyalanır
    if (text) { try { navigator.clipboard.writeText(text).catch(() => {}); } catch { /* izin yok */ } }
    window.open(config.sanctionedAiUrl, "_blank", "noopener");
  }
  /** Pencere düğmesi: tanımlıysa "<ad> ile devam et" (metin panoya kopyalanır). */
  const redirectButton = (base, text, onDone = () => {}) => config.sanctionedAiUrl ? [{
    label: `${sanctionedName()} ile devam et`,
    onClick: () => { send({ ...base, action: "redirected" }); openSanctioned(text); onDone(); },
  }] : [];

  // ---------- "yine de" gerekçesi ----------
  const JUSTIFICATIONS = [
    ["consent", "Müşteri / ilgili kişi onayı var"], ["test_data", "Test ya da sahte veri"],
    ["false_positive", "Yanlış alarm: hassas veri değil"], ["other", "Diğer"],
  ];
  /** Gerekçe seçilince onChosen(gerekçe); vazgeçilince onCancel. MDM'de kapalıysa doğrudan devam. */
  function withJustification(onChosen, onCancel = () => {}) {
    if (config.requireJustification === false) { onChosen(undefined); return; }
    dialog({
      title: "Neden göndermeniz gerekiyor?",
      message: "Seçiminiz denetim kaydına yazılır (metin yazılmaz). \"Yanlış alarm\" seçimleri tespit kurallarını iyileştirmek için kullanılır.",
      buttons: [{ label: "Vazgeç", cancel: true, onClick: onCancel },
        ...JUSTIFICATIONS.map(([key, label]) => ({ label, onClick: () => onChosen(key) }))],
    });
  }

  function showBanner() {
    if (!config.sanctionedAiUrl || config.showBanner === false) return;
    try { if (sessionStorage.getItem("telveguard-banner")) return; sessionStorage.setItem("telveguard-banner", "1"); } catch { return; }
    const host = document.createElement("div");
    host.setAttribute("data-telveguard", "");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = BANNER_STYLE;
    const box = document.createElement("div");
    box.className = "banner";
    box.setAttribute("role", "status");
    const p = document.createElement("p");
    p.textContent = `Bu site kurum dışı bir yapay zekâ hizmeti. Müşteri, kişisel ya da kurum verisi için ${sanctionedName()} kullanın.`;
    const open = document.createElement("button");
    open.className = "primary";
    open.textContent = "Aç";
    open.addEventListener("click", () => { host.remove(); send({ action: "redirected", trigger: "banner" }); openSanctioned(""); });
    const close = document.createElement("button");
    close.textContent = "Tamam";
    close.addEventListener("click", () => host.remove());
    const row = document.createElement("div");
    row.className = "row";
    row.append(close, open);
    box.append(p, row);
    root.append(style, box);
    const mount = () => (document.body || document.documentElement).append(host);
    if (document.body) mount(); else addEventListener("DOMContentLoaded", mount, { once: true });
    window.__telveguardBanner = { host, open, close };   // testler için
  }

  function insert(target, text) {
    // Sitelerin editörleri (React / ProseMirror) input olayını görsün diye tarayıcının komutu
    if (target && typeof target.focus === "function") target.focus();
    if (document.execCommand && document.execCommand("insertText", false, text)) return;
    if (target && "value" in target && typeof target.setRangeText === "function") {
      target.setRangeText(text, target.selectionStart ?? target.value.length, target.selectionEnd ?? target.value.length, "end");
      target.dispatchEvent(new Event("input", { bubbles: true }));
    }
  }

  // ---------- pencere ----------
  const STYLE = `
    :host { all: initial; }
    .back { position: fixed; inset: 0; background: rgba(0,0,0,.35); display: flex; align-items: center;
            justify-content: center; z-index: 2147483647; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
    .box { background: #fcfcfb; color: #0b0b0b; border-radius: 12px; padding: 20px; max-width: 440px; width: calc(100% - 32px);
           box-shadow: 0 12px 40px rgba(0,0,0,.25); }
    h2 { font-size: 16px; margin: 0 0 8px; }
    p { margin: 0 0 10px; color: #52514e; }
    ul { margin: 0 0 14px; padding-left: 18px; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    button { font: inherit; border-radius: 8px; padding: 8px 12px; border: 1px solid rgba(11,11,11,.15);
             background: #fcfcfb; color: #0b0b0b; cursor: pointer; }
    button.primary { background: #0b0b0b; color: #fff; border-color: transparent; }
    button:focus-visible { outline: 2px solid #2a78d6; outline-offset: 2px; }
    .muted { font-size: 12px; color: #898781; margin-top: 10px; }
    button:disabled { opacity: .45; cursor: default; }
    .box { max-height: calc(100vh - 32px); overflow-y: auto; box-sizing: border-box; }
    .preview { display: block; width: 100%; height: 0; border: 0; margin: 0 0 14px; }
    .preview[hidden] { display: block !important; visibility: hidden; height: 0 !important; margin: 0; }   /* ölçülebilsin */
    ul[hidden] { display: none; }
    @media (prefers-color-scheme: dark) {
      .box { background: #1a1a19; color: #fff; } p { color: #c3c2b7; }
      button { background: #1a1a19; color: #fff; border-color: rgba(255,255,255,.15); }
      button.primary { background: #fff; color: #0b0b0b; }
    }`;

  const BANNER_STYLE = `
    :host { all: initial; }
    .banner { position: fixed; right: 16px; bottom: 16px; z-index: 2147483646; max-width: 360px; background: #fcfcfb;
              color: #0b0b0b; border-radius: 12px; padding: 12px 14px; box-shadow: 0 8px 28px rgba(0,0,0,.22);
              font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; border-left: 4px solid #8a4b1f; }
    p { margin: 0 0 8px; }
    .row { display: flex; gap: 8px; justify-content: flex-end; }
    button { font: inherit; border-radius: 8px; padding: 5px 10px; border: 1px solid rgba(11,11,11,.15); background: #fcfcfb;
             color: #0b0b0b; cursor: pointer; }
    button.primary { background: #0b0b0b; color: #fff; border-color: transparent; }
    @media (prefers-color-scheme: dark) {
      .banner { background: #1a1a19; color: #fff; }
      button { background: #1a1a19; color: #fff; border-color: rgba(255,255,255,.15); }
      button.primary { background: #fff; color: #0b0b0b; }
    }`;

  // ---------- yerel geri açma ----------
  let pageVault = null;   // { counters, seen, values }: yalnızca bu sayfanın belleğinde
  let revealStarted = false;
  function remember(state) {
    pageVault = state;
    if (config.revealPlaceholders !== false && !revealStarted) { revealStarted = true; startReveal(); }
  }
  const PLACEHOLDER_RX = /\[[A-Z][A-Z0-9_]*_\d+\]/g;
  const restorePlaceholders = (t) => t.replace(PLACEHOLDER_RX, (ph) => (pageVault && pageVault.values.get(ph)) ?? ph);

  /** İmlecin altındaki bilinen yer tutucu. Sitenin DOM'u değiştirilmez: metin konumu tarayıcıdan sorulur. */
  function placeholderAt(x, y) {
    let node, offset;
    if (document.caretPositionFromPoint) {
      const p = document.caretPositionFromPoint(x, y);
      if (p) { node = p.offsetNode; offset = p.offset; }
    } else if (document.caretRangeFromPoint) {
      const r = document.caretRangeFromPoint(x, y);
      if (r) { node = r.startContainer; offset = r.startOffset; }
    }
    if (!node || node.nodeType !== 3) return null;
    for (const m of node.data.matchAll(PLACEHOLDER_RX)) {
      const end = m.index + m[0].length;
      if (offset < m.index || offset > end || !pageVault.values.has(m[0])) continue;
      const range = document.createRange();
      range.setStart(node, m.index);
      range.setEnd(node, end);
      // Satır sonundaki boşluğa gelince de imleç son karakterde görünür: gerçekten üzerinde mi?
      if ([...range.getClientRects()].some((b) => x >= b.left && x <= b.right && y >= b.top && y <= b.bottom)) return m[0];
    }
    return null;
  }

  const FRAME_URL = hasRuntime && chrome.runtime.getURL ? chrome.runtime.getURL("preview.html") : "";

  /** Hassas değerlerin çerçevesi: başlangıçta gizli. Yüklenemezse (sitenin CSP'si) ready gelmez, gizli kalır. */
  const FRAME_TIMEOUT_MS = 3000;
  function reportFrame(ok) {
    frameFailed = !ok;
    if (hasRuntime) { try { chrome.runtime.sendMessage({ type: "previewStatus", site, ok }); } catch { /* eklenti yenilendi */ } }
  }

  function secureFrame(onMessage) {
    const frame = document.createElement("iframe");
    frame.hidden = true;
    frame.title = "Telveguard önizleme";
    if (!FRAME_URL) return { frame, post: () => {} };
    frame.src = FRAME_URL;
    const channel = new MessageChannel();
    let answered = false;
    const timer = setTimeout(() => { if (!answered) reportFrame(false); }, FRAME_TIMEOUT_MS);
    channel.port1.onmessage = (m) => {
      if (m.data.type === "ready" && !answered) { answered = true; clearTimeout(timer); reportFrame(true); }
      onMessage(m.data);
    };
    frame.addEventListener("load", () => {
      // Hedef köken eklenti: site çerçeveyi değiştirse de mesaj ve kanal ona gitmez
      try { frame.contentWindow.postMessage("telveguard-init", new URL(FRAME_URL).origin, [channel.port2]); }
      catch { /* çerçeve yüklenemedi: gizli kalır */ }
    }, { once: true });
    return { frame, post: (m) => channel.port1.postMessage(m) };
  }

  function startReveal() {
    const host = document.createElement("div");
    host.setAttribute("data-telveguard", "");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = REVEAL_STYLE;
    let at = { x: 0, y: 0 }, shown = "", size = null;
    const place = (el, x, y, width, height) => {
      el.style.left = `${Math.max(8, Math.min(x, innerWidth - width - 8))}px`;
      el.style.top = `${y + height + 12 > innerHeight ? y - height - 8 : y + 12}px`;
    };
    const { frame: tip, post } = secureFrame((m) => {
      if (m.type !== "size" || !shown) return;
      size = m;
      tip.style.width = `${m.width}px`;
      tip.style.height = `${m.height}px`;
      place(tip, at.x, at.y, m.width, m.height);
      tip.hidden = false;
    });
    tip.className = "tip";
    const copy = document.createElement("button");
    copy.type = "button";
    copy.hidden = true;
    root.append(style, tip, copy);
    (document.body || document.documentElement).append(host);
    window.__telveguardReveal = { host, tip, copy };   // testler için

    let frameId = 0;
    window.addEventListener("mousemove", (ev) => {
      if (!ev.isTrusted || frameId) return;     // sitenin sahte olayı ipucunu tetiklemesin
      if (config.revealPlaceholders === false) { shown = ""; tip.hidden = true; return; }   // MDM anında geçerli
      frameId = requestAnimationFrame(() => {
        frameId = 0;
        const ph = placeholderAt(ev.clientX, ev.clientY);
        at = { x: ev.clientX, y: ev.clientY };
        if (ph === shown && !tip.hidden && size) { place(tip, at.x, at.y, size.width, size.height); return; }
        shown = ph || "";
        tip.hidden = true;
        if (!ph) return;
        tip.style.width = "360px";   // geniş ölç, sonra içeriğe göre daralt
        const entity = ph.slice(1, -1).replace(/_\d+$/, "");
        post({ kind: "tip", text: `${D.label(entity)}: ${showValue(entity, pageVault.values.get(ph))}` });
      });
    }, { passive: true, capture: true });
    window.addEventListener("scroll", () => { shown = ""; tip.hidden = true; copy.hidden = true; }, { passive: true, capture: true });

    let restored = "";
    const checkSelection = (ev) => {
      if (!ev.isTrusted || ev.target === host) return;
      if (config.revealCopy !== true || config.revealPlaceholders === false) { copy.hidden = true; return; }
      setTimeout(() => {
        const sel = getSelection();
        const text = sel && sel.rangeCount ? sel.toString() : "";
        restored = text ? restorePlaceholders(text) : "";
        copy.hidden = !restored || restored === text;
        if (copy.hidden) return;
        copy.textContent = "Aslıyla kopyala";
        const rects = sel.getRangeAt(0).getClientRects();
        const last = rects[rects.length - 1];
        if (last) { const b = copy.getBoundingClientRect(); place(copy, last.right, last.bottom, b.width, b.height); }
      }, 0);
    };
    window.addEventListener("mouseup", checkSelection, true);
    window.addEventListener("keyup", checkSelection, true);
    copy.addEventListener("mousedown", (ev) => ev.preventDefault());   // seçim kaybolmasın
    copy.addEventListener("click", (ev) => {
      if (!ev.isTrusted) return;
      // Sitenin copy olayı kullanılmaz: değer sitenin betiğine görünürdü
      navigator.clipboard.writeText(restored).then(() => { copy.textContent = "Kopyalandı"; }, () => { copy.textContent = "Kopyalanamadı"; });
      setTimeout(() => { copy.hidden = true; }, 1200);
    });
  }

  // ---------- maskeli önizleme ----------
  const PREVIEW_MAX_VALUES = 30;
  // Sırlar pencerede tam görünmesin (ekran paylaşımı); hangisi olduğu ilk karakterlerden anlaşılır
  const showValue = (entity, value) => entity.startsWith("SECRET_") ? value.slice(0, 4) + "…"
    : value.length > 48 ? value.slice(0, 47) + "…" : value;

  /** Yakalanan değerler (çerçevede; varsayılan kapalı, "Değerleri göster" ile açılır). selectable: değerin
   *  işareti kaldırılabilir. Seçim durumu burada tutulur; çerçeve yalnızca gösterir ve tıklamayı bildirir. */
  function previewPanel(text, findings, { selectable = false, caption = "", state = pageVault } = {}) {
    const maskWith = (chosen) => D.mask(text, { continueNumbering: true, findings: chosen, state });
    const groups = new Map();   // yer tutucu -> aynı değerin tüm geçişleri (farklı yazımlar dahil)
    for (const f of maskWith(findings).findings) {
      if (!groups.has(f.placeholder)) groups.set(f.placeholder, { members: [], on: true });
      groups.get(f.placeholder).members.push(f);
    }
    const list = [...groups.values()];
    const pick = (on) => list.filter((g) => g.on === on).flatMap((g) => g.members).sort((a, b) => a.start - b.start);
    const maskChosen = () => maskWith(pick(true));

    function model() {
      const placeholders = new Map(maskChosen().findings.map((f) => [f.start, f.placeholder]));
      const rows = list.slice(0, PREVIEW_MAX_VALUES).map((g) => {
        const first = g.members[0];
        return { label: D.label(first.entity), value: showValue(first.entity, text.slice(first.start, first.end)), on: g.on,
                 ph: g.on ? `→ ${placeholders.get(first.start)}` : "maskelenmez" };
      });
      return { kind: "preview", selectable, caption, rows, count: list.length,
               more: list.length > PREVIEW_MAX_VALUES ? `ve ${list.length - PREVIEW_MAX_VALUES} değer daha (hepsi maskelenir)` : "" };
    }

    const panel = { selected: () => pick(true), kept: () => pick(false), selectable, ready: false,
                    onChange: () => {}, onEscape: () => {}, onLeave: () => {},
                    masked: () => { const m = maskChosen(); remember(m.state); return m.text; } };
    const { frame, post } = secureFrame((m) => {
      if (m.type === "ready") post(model());
      if (m.type === "size") {
        frame.style.height = `${m.height}px`;
        if (!panel.ready) { panel.ready = true; frame.hidden = false; }
      }
      if (m.type === "toggle" && list[m.i]) { list[m.i].on = !list[m.i].on; post(model()); panel.onChange(); }
      if (m.type === "escape") panel.onEscape();
      if (m.type === "leave") panel.onLeave(m.back);
    });
    frame.className = "preview";
    panel.el = frame;
    panel.focus = (last) => { frame.focus(); post({ kind: "focus", last }); };
    return panel;
  }

  /** "Maskele" seçimi: maskelenenler "masked", işareti kaldırılanlar yanlış alarm beyanı olarak kayda gider. */
  function recordMasking(text, base, panel) {
    send({ ...base, entities: counts(panel.selected()), action: "masked" });
    const kept = panel.kept();
    if (!kept.length) return;
    allow(text, kept);
    send({ ...base, entities: counts(kept), action: "allowed_override", justification: "false_positive" });
  }

  const REVEAL_STYLE = `
    :host { all: initial; }
    .tip, button { position: fixed; z-index: 2147483646; border-radius: 6px; box-shadow: 0 4px 16px rgba(0,0,0,.3); }
    .tip { pointer-events: none; border: 0; width: 360px; height: 0; }
    .tip[hidden] { display: block !important; visibility: hidden; }   /* ölçülebilsin */
    button[hidden] { display: none; }
    button { font: 12px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; background: #0b0b0b; color: #fff; padding: 5px 8px; border: 0; cursor: pointer; }
    button:focus-visible { outline: 2px solid #2a78d6; outline-offset: 2px; }
    @media (prefers-color-scheme: dark) { button { background: #fff; color: #0b0b0b; } }`;

  function dialog({ title, message, items, summary, previews = [], buttons }) {
    const host = document.createElement("div");
    host.setAttribute("data-telveguard", "");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    const back = document.createElement("div");
    back.className = "back";
    const box = document.createElement("div");
    box.className = "box";
    box.setAttribute("role", "alertdialog");
    box.setAttribute("aria-modal", "true");
    const h = document.createElement("h2");
    h.textContent = title;
    const p = document.createElement("p");
    p.textContent = message;
    box.append(h, p);
    const list = (lines) => {
      const ul = document.createElement("ul");
      for (const it of lines) { const li = document.createElement("li"); li.textContent = it; ul.append(li); }
      box.append(ul);
      return ul;
    };
    if (items && items.length) list(items);
    // summary: tür ve adet, her zaman görünür; değerler çerçevede istenirse açılır (çerçeve açılmazsa yalnızca özet)
    if (summary && summary.length) list(summary);
    previews.forEach((pv) => box.append(pv.el));
    const row = document.createElement("div");
    row.className = "row";
    const close = () => host.remove();
    const els = buttons.map((b) => {
      const el = document.createElement("button");
      el.type = "button";
      el.textContent = b.label;
      if (b.primary) el.className = "primary";
      el.addEventListener("click", () => { close(); b.onClick && b.onClick(); });
      row.append(el);
      return el;
    });
    // Tüm işaretler kaldırılınca "maskele" düğmesi kapanır: hiçbir şey maskelenmeyecekse yol "Yine de"dir (gerekçeli)
    const refresh = () => buttons.forEach((b, i) => { if (b.enabled) els[i].disabled = !b.enabled(); });
    const cancel = () => { close(); const c = buttons.find((b) => b.cancel); c && c.onClick && c.onClick(); };
    previews.forEach((pv) => {
      pv.onChange = refresh;
      pv.onEscape = cancel;
      pv.onLeave = (back) => { const on = els.filter((b) => !b.disabled); (back ? on[on.length - 1] : on[0]).focus(); };
    });
    const note = document.createElement("div");
    note.className = "muted";
    note.textContent = "Telveguard · metin bilgisayarınızdan çıkmadan tarandı.";
    box.append(row, note);
    back.append(box);
    root.append(style, back);
    back.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault(); cancel(); }
      if (e.key === "Tab") {           // odak pencerede kalsın (çerçevedeki düğme ve işaretler dahil)
        const frames = previews.filter((pv) => pv.ready);
        const focusable = [...frames.map((pv) => pv.el), ...els.filter((b) => !b.disabled)];
        const i = focusable.indexOf(root.activeElement);
        const next = focusable[e.shiftKey ? (i <= 0 ? focusable.length - 1 : i - 1) : (i + 1) % focusable.length];
        e.preventDefault();
        const frame = frames.find((pv) => pv.el === next);
        if (frame) frame.focus(e.shiftKey); else next.focus();
      }
    });
    (document.body || document.documentElement).append(host);
    (els.find((_, i) => buttons[i].primary) || els[0]).focus();
    window.__telveguardDialog = { host, root, buttons: els, previews };   // testler için
    return host;
  }

  // ---------- yapıştırma ----------
  function onPaste(ev) {
    if (redispatching) return;
    const files = ev.clipboardData ? [...ev.clipboardData.files] : [];
    if (files.length && needsReview(files)) {
      holdFiles(ev, files, (out) => deliverPastedFiles(ev.target, out));
      return;
    }
    const text = ev.clipboardData && ev.clipboardData.getData("text/plain");
    if (!text) return;
    const findings = D.analyze(text);
    if (!findings.length) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    const target = ev.target;
    const c = counts(findings);
    const base = { entities: c, chars: text.length, trigger: "paste" };

    if (config.mode === "block") {
      send({ ...base, action: "blocked" });
      dialog({ title: "Yapıştırma engellendi", summary: describe(c), previews: [previewPanel(text, findings)],
               buttons: [{ label: "Tamam", primary: !config.sanctionedAiUrl, cancel: true },
                 ...redirectButton(base, text).map((b) => ({ ...b, primary: true }))],
               message: "Kurum politikası gereği kişisel veri, sır ya da kurum bilgisi içeren metin AI sitelerine yapıştırılamaz." +
                 (config.sanctionedAiUrl ? ` ${sanctionedName()} ile devam ederseniz metin panoya kopyalanır.` : "") });
      return;
    }
    const preview = previewPanel(text, findings, { selectable: true });
    dialog({
      title: "Hassas veri tespit edildi",
      message: "Yapıştırdığınız metin şunları içeriyor. Maskeleyerek yapıştırırsanız değerlerin yerine [TCKN_1] gibi yer tutucular gider; " +
        "hassas olmayan değerin işaretini kaldırabilirsiniz." +
        (config.sanctionedAiUrl ? ` Metnin aslıyla çalışmanız gerekiyorsa ${sanctionedName()} kullanın.` : ""),
      summary: describe(c),
      previews: [preview],
      buttons: [
        { label: "Vazgeç", cancel: true, onClick: () => send({ ...base, action: "cancelled" }) },
        { label: "Yine de yapıştır", onClick: () => withJustification((justification) => {
          allow(text, findings); insert(target, text); send({ ...base, action: "allowed_override", justification }); },
          () => send({ ...base, action: "cancelled" })) },
        ...redirectButton(base, text),
        { label: "Maskeleyerek yapıştır", primary: true, enabled: () => preview.selected().length > 0,
          onClick: () => { insert(target, preview.masked()); recordMasking(text, base, preview); } },
      ],
    });
  }

  // ---------- dosya ekleme ----------
  // Metin dosyaları tarayıcıda okunup taranır; olay durdurulur, karar sonrası (temizse olduğu gibi,
  // maskelendiyse maskeli kopyayla) siteye yeniden verilir. PDF / görsel / Office taranamaz.
  const TEXT_EXT = /\.(txt|text|csv|tsv|md|markdown|json|jsonl|ndjson|xml|ya?ml|log|sql|ini|cfg|conf|env|properties|toml|html?|css|scss|js|mjs|cjs|jsx|ts|tsx|py|ipynb|java|kt|kts|cs|go|rb|php|sh|bash|zsh|ps1|bat|c|h|cc|cpp|hpp|rs|swift|scala|r|tf|tfvars|gradle|vue|svelte|pem|key)$/i;
  const TEXT_MIME = /^text\/|[/+](json|xml|yaml|x-yaml|javascript|x-sh|sql|x-python|x-pem-file)$/i;
  const MAX_FILE_BYTES = 5 * 1024 * 1024;
  const scannable = (f) => f.size <= MAX_FILE_BYTES && (TEXT_MIME.test(f.type || "") || TEXT_EXT.test(f.name || ""));
  const needsReview = (files) => files.some(scannable) || (config.unscannableFiles === "block" && files.length > 0);

  let redispatching = false;
  function redispatch(target, event) {
    redispatching = true;
    try { (target || document.body).dispatchEvent(event); } finally { redispatching = false; }
  }

  // Firefox ClipboardEvent'e verilen clipboardData'yı yok sayar: dosya sessizce kaybolmasın diye
  // sayfanın dosya girdisinden, o da yoksa sürükle-bırak olayıyla verilir
  function deliverPastedFiles(target, files) {
    const dt = new DataTransfer();
    files.forEach((f) => dt.items.add(f));
    const paste = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true, composed: true });
    if (paste.clipboardData && paste.clipboardData.files.length === files.length) { redispatch(target, paste); return; }
    const input = document.querySelector("input[type=file]");
    if (input) {
      input.files = dt.files;
      redispatch(input, new Event("input", { bubbles: true, composed: true }));
      redispatch(input, new Event("change", { bubbles: true }));
      return;
    }
    redispatch(target, new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true, composed: true }));
  }

  /** Dosyaları tarar; kullanıcı kararına göre onDone(eklenecek dosyalar) çağrılır (vazgeçince çağrılmaz). */
  async function reviewFiles(files, onDone, onCancel = () => {}) {
    const hits = [], unscannable = [];
    let chars = 0;
    const out = await Promise.all(files.map(async (f) => {
      if (!scannable(f)) { unscannable.push(f); return f; }
      const text = await f.text().catch(() => null);
      if (text === null) { unscannable.push(f); return f; }
      const findings = D.analyze(text);
      if (!findings.length) return f;
      chars += text.length;
      hits.push({ file: f, findings, text });
      return f;
    }));
    // Dosyalar sırayla numaralanır (aynı değer her dosyada aynı yer tutucu); state "Maskeleyerek ekle" ile saklanır
    let state = pageVault;
    for (const h of hits) {
      h.state = state;
      const m = D.mask(h.text, { continueNumbering: true, findings: h.findings, state });
      h.masked = new File([m.text], h.file.name, { type: h.file.type || "text/plain", lastModified: h.file.lastModified });
      state = m.state;
    }
    const blockedUnscannable = config.unscannableFiles === "block" ? unscannable : [];
    if (!hits.length && !blockedUnscannable.length) { onDone(files); return; }

    const c = {};
    hits.forEach((h) => counts(h.findings, c));
    const base = { entities: c, chars, trigger: "file" };
    const items = hits.map((h) => `${h.file.name}: ${describe(counts(h.findings)).join(", ")}`)
      .concat(blockedUnscannable.map((f) => `${f.name}: taranamayan dosya türü`));
    // Dosyada önizleme salt okunur ve ilk 5 dosya için; kalanı yukarıdaki listede tür ve adetle görünür
    const previews = hits.slice(0, 5).map((h) => previewPanel(h.text, h.findings, { caption: h.file.name, state: h.state }));

    if (config.mode === "block" || blockedUnscannable.length) {
      send({ ...base, action: "blocked" });
      dialog({ title: "Dosya eklenmedi", items, previews, buttons: [{ label: "Tamam", primary: true, cancel: true, onClick: onCancel }],
               message: hits.length && config.mode === "block"
                 ? "Kurum politikası gereği kişisel veri, sır ya da kurum bilgisi içeren dosyalar AI sitelerine eklenemez."
                 : "Kurum politikası gereği taranamayan dosyalar (PDF, görsel, Office belgeleri) AI sitelerine eklenemez." });
      return;
    }
    const maskedOut = out.map((f) => (hits.find((h) => h.file === f) || { masked: f }).masked);
    dialog({
      title: "Dosyada hassas veri var",
      message: "Eklediğiniz dosyalar şunları içeriyor. Maskeleyerek eklerseniz siteye değerlerin yerine [TCKN_1] gibi " +
               "yer tutucuların olduğu bir kopya gider; bilgisayarınızdaki dosya değişmez.",
      items,
      previews,
      buttons: [
        { label: "Vazgeç", cancel: true, onClick: () => { send({ ...base, action: "cancelled" }); onCancel(); } },
        { label: "Yine de ekle", onClick: () => withJustification((justification) => {
          send({ ...base, action: "allowed_override", justification }); onDone(files); },
          () => { send({ ...base, action: "cancelled" }); onCancel(); }) },
        { label: "Maskeleyerek ekle", primary: true, onClick: () => { remember(state); send({ ...base, action: "masked" }); onDone(maskedOut); } },
      ],
    });
  }

  function holdFiles(ev, files, onDone, onCancel) {
    ev.preventDefault();
    ev.stopImmediatePropagation();
    reviewFiles(files, onDone, onCancel);
  }

  // Sürükle-bırak
  window.addEventListener("drop", (ev) => {
    if (redispatching || !ev.dataTransfer) return;
    const files = [...ev.dataTransfer.files];
    if (!files.length || !needsReview(files)) return;
    const init = { bubbles: true, cancelable: true, composed: true, clientX: ev.clientX, clientY: ev.clientY,
                   screenX: ev.screenX, screenY: ev.screenY };
    const target = ev.target;
    holdFiles(ev, files, (out) => {
      const dt = new DataTransfer();
      out.forEach((f) => dt.items.add(f));
      redispatch(target, new DragEvent("drop", { ...init, dataTransfer: dt }));
    }, () => redispatch(target, new DragEvent("dragleave", init)));   // sitenin "bırakın" katmanı kapansın
  }, true);

  // Dosya seçme (<input type=file>): tarayıcı önce input sonra change verir; ikisi de karar
  // verilene kadar siteye ulaşmaz, sonra aynı sırayla yeniden verilir
  const fileInputOf = (t) => t && t.tagName === "INPUT" && t.type === "file" && t.files && t.files.length ? t : null;
  window.addEventListener("input", (ev) => {
    const input = fileInputOf(ev.target);
    if (!redispatching && input && needsReview([...input.files])) ev.stopImmediatePropagation();
  }, true);
  window.addEventListener("change", (ev) => {
    const input = fileInputOf(ev.target);
    if (redispatching || !input) return;
    const files = [...input.files];
    if (!needsReview(files)) return;
    ev.stopImmediatePropagation();
    reviewFiles(files, (out) => {
      if (out !== files) {
        const dt = new DataTransfer();
        out.forEach((f) => dt.items.add(f));
        input.files = dt.files;
      }
      redispatch(input, new Event("input", { bubbles: true, composed: true }));
      redispatch(input, new Event("change", { bubbles: true }));
    }, () => { input.value = ""; });
  }, true);

  // window: sitenin window yakalama dinleyicisi metni bizden önce görmesin (document_start: önce biz kaydoluruz)
  window.addEventListener("paste", onPaste, true);

  // ---------- gönderim ----------
  // Sohbet kutusu: textarea ya da contenteditable (ChatGPT / Claude / Gemini: ProseMirror, Quill)
  function composerOf(node) {
    if (!node || node.nodeType !== 1) return null;
    if (node.tagName === "TEXTAREA") return node;
    if (!node.isContentEditable) return null;
    let root = node;
    while (root.parentElement && root.parentElement.isContentEditable) root = root.parentElement;
    return root;
  }
  const composerText = (el) => el.tagName === "TEXTAREA" ? el.value : el.innerText;
  let lastComposer = null;
  // Düğmenin kabındaki (form ya da en yakın ortak ata) sohbet kutusu; yoksa son odaklanılan
  function composerNear(button) {
    for (let box = button.parentElement; box && box !== document.documentElement; box = box.parentElement) {
      const c = [...box.querySelectorAll("textarea, [contenteditable='true'], [contenteditable='']")]
        .map(composerOf).find((x) => x && composerText(x).trim());
      if (c) return c;
    }
    const active = composerOf(document.activeElement);
    return active || (lastComposer && document.contains(lastComposer) ? lastComposer : null);
  }
  document.addEventListener("focusin", (e) => { const c = composerOf(e.target); if (c) lastComposer = c; }, true);

  // Gönder düğmesi: sitelerin ortak işaretleri (aria-label / data-testid / type=submit)
  const SEND_RX = /\b(send|submit|gönder|ilet)/i;
  function sendButtonOf(node) {
    const b = node && node.closest && node.closest("button, [role='button']");
    if (!b || b.closest("[data-telveguard]")) return null;
    const hint = [b.getAttribute("aria-label"), b.getAttribute("data-testid"), b.getAttribute("title"), b.className]
      .filter((x) => typeof x === "string").join(" ");
    return b.getAttribute("type") === "submit" || SEND_RX.test(hint) ? b : null;
  }
  function findSendButton(composer) {
    // Kutunun en yakın ortak kabında görünür bir gönder düğmesi
    for (let box = composer.parentElement; box && box !== document.body; box = box.parentElement) {
      const b = [...box.querySelectorAll("button, [role='button']")].find((x) => sendButtonOf(x) && !x.disabled);
      if (b) return b;
    }
    return null;
  }

  // "Yine de gönder" / maskeleme sonrası yeniden gönderim: yalnızca BİR sonraki gönderim geçer
  // (kısa süreli; kullanıcının hemen ardından yazdığı başka mesaj yine taranır)
  let bypassUntil = 0;
  let dialogOpen = false;

  function resend(composer, via) {
    bypassUntil = Date.now() + 1500;
    const b = via || findSendButton(composer);
    if (b) { b.click(); return; }
    composer.focus();
    composer.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, bubbles: true, cancelable: true }));
  }

  function replaceComposer(composer, text) {
    composer.focus();
    if (composer.tagName === "TEXTAREA") composer.select();
    else { const sel = getSelection(); sel.removeAllRanges(); const r = document.createRange(); r.selectNodeContents(composer); sel.addRange(r); }
    insert(composer, text);
  }

  /** true: gönderim durduruldu (pencere açıldı). */
  function guardSend(ev, composer, button) {
    if (dialogOpen) { ev.preventDefault(); ev.stopImmediatePropagation(); return true; }
    if (Date.now() < bypassUntil) { bypassUntil = 0; return false; }
    if (!composer) return false;
    const text = composerText(composer);
    if (!text || !text.trim()) return false;
    // Engelle modunda istisna yok: "yine de" denmiş değer (ör. mod değişmeden önce) geçmez
    const findings = D.analyze(text).filter((f) => config.mode === "block" || !allowedValues.has(text.slice(f.start, f.end)));
    if (!findings.length) return false;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    const c = counts(findings);
    const base = { entities: c, chars: text.length, trigger: "send" };
    const done = () => { dialogOpen = false; };
    dialogOpen = true;

    if (config.mode === "block") {
      const preview = previewPanel(text, findings);
      send({ ...base, action: "blocked" });
      dialog({ title: "Gönderim engellendi", summary: describe(c), previews: [preview], message: "Kurum politikası gereği kişisel veri, sır ya da kurum bilgisi içeren mesaj " +
                 "AI sitelerine gönderilemez. Metni maskeleyip kontrol ettikten sonra tekrar gönderebilirsiniz.",
               buttons: [
                 { label: "Düzenle", cancel: true, onClick: () => { done(); composer.focus(); } },
                 ...redirectButton(base, text, done),
                 { label: "Metni maskele", primary: true, onClick: () => { done(); replaceComposer(composer, preview.masked()); } },
               ] });
      return true;
    }
    const preview = previewPanel(text, findings, { selectable: true });
    dialog({
      title: "Göndermeden önce",
      message: "Mesajınız şunları içeriyor. Maskeleyerek gönderirseniz değerlerin yerine [TCKN_1] gibi yer tutucular gider; " +
        "hassas olmayan değerin işaretini kaldırabilirsiniz." +
        (config.sanctionedAiUrl ? ` Metnin aslıyla çalışmanız gerekiyorsa ${sanctionedName()} kullanın (metin panoya kopyalanır).` : ""),
      summary: describe(c),
      previews: [preview],
      buttons: [
        { label: "Düzenle", cancel: true, onClick: () => { done(); send({ ...base, action: "cancelled" }); composer.focus(); } },
        { label: "Yine de gönder", onClick: () => withJustification((justification) => {
          done(); allow(text, findings); send({ ...base, action: "allowed_override", justification }); resend(composer, button); },
          () => { done(); send({ ...base, action: "cancelled" }); composer.focus(); }) },
        ...redirectButton(base, text, done),
        { label: "Maskele ve gönder", primary: true, enabled: () => preview.selected().length > 0, onClick: () => {
          done(); replaceComposer(composer, preview.masked()); recordMasking(text, base, preview);
          // Editör (React / ProseMirror) yeni metni işlesin, sonra gönder
          setTimeout(() => resend(composer, button), 50); } },
      ],
    });
    return true;
  }

  // Enter (Shift+Enter yeni satırdır) ve Ctrl/Cmd+Enter; IME ile yazarken (Türkçe dışı klavyeler) dokunma
  window.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter" || ev.shiftKey || ev.isComposing || ev.keyCode === 229) return;
    const composer = composerOf(ev.target);
    if (composer) guardSend(ev, composer, null);
  }, true);

  // Gönder düğmesi (fare / dokunma / klavye ile tıklama)
  window.addEventListener("click", (ev) => {
    const button = sendButtonOf(ev.target);
    if (!button) return;
    guardSend(ev, composerNear(button), button);
  }, true);
})();
