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
 * Telveguard'a yalnızca site, veri türü adetleri ve karar gider; metin asla gönderilmez.
 * Pencere Shadow DOM'da: sitenin CSS'i bozamaz, sitenin betikleri içeriğini okuyamaz.
 */
(function () {
  "use strict";
  const D = self.TelveguardDetectors;
  if (!D || window.__telveguardLoaded) return;
  window.__telveguardLoaded = true;

  const site = location.hostname.replace(/^www\./, "");
  let config = { mode: "warn", reportVisits: false, unscannableFiles: "allow" };
  const hasRuntime = typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage;

  function send(event) {
    if (!hasRuntime) return;
    try { chrome.runtime.sendMessage({ type: "event", event: { site, ...event } }); } catch { /* eklenti yenilendi */ }
  }

  if (hasRuntime) {
    try {
      chrome.runtime.sendMessage({ type: "getConfig" }, (c) => {
        if (c) config = c;
        if (config.reportVisits && !sessionStorage.getItem("telveguard-visit")) {
          try { sessionStorage.setItem("telveguard-visit", "1"); } catch { /* yok say */ }
          send({ action: "visit" });
        }
      });
    } catch { /* varsayılan yapılandırma */ }
  }

  const DICT_KEY = "telveguardDictionary";
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    try {
      chrome.storage.local.get(DICT_KEY, (v) => D.setDictionary(v && v[DICT_KEY]));
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes[DICT_KEY]) D.setDictionary(changes[DICT_KEY].newValue);
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
    @media (prefers-color-scheme: dark) {
      .box { background: #1a1a19; color: #fff; } p { color: #c3c2b7; }
      button { background: #1a1a19; color: #fff; border-color: rgba(255,255,255,.15); }
      button.primary { background: #fff; color: #0b0b0b; }
    }`;

  function dialog({ title, message, items, buttons }) {
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
    if (items && items.length) {
      const ul = document.createElement("ul");
      for (const it of items) { const li = document.createElement("li"); li.textContent = it; ul.append(li); }
      box.append(ul);
    }
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
    const note = document.createElement("div");
    note.className = "muted";
    note.textContent = "Telveguard · metin bilgisayarınızdan çıkmadan tarandı.";
    box.append(row, note);
    back.append(box);
    root.append(style, back);
    back.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault(); close(); const c = buttons.find((b) => b.cancel); c && c.onClick(); }
      if (e.key === "Tab") {           // odak pencerede kalsın
        const i = els.indexOf(root.activeElement);
        const next = e.shiftKey ? (i <= 0 ? els.length - 1 : i - 1) : (i + 1) % els.length;
        e.preventDefault(); els[next].focus();
      }
    });
    (document.body || document.documentElement).append(host);
    (els.find((_, i) => buttons[i].primary) || els[0]).focus();
    window.__telveguardDialog = { host, root, buttons: els };   // testler için
    return host;
  }

  // ---------- yapıştırma ----------
  function onPaste(ev) {
    if (redispatching) return;
    const files = ev.clipboardData ? [...ev.clipboardData.files] : [];
    if (files.length && needsReview(files)) {
      holdFiles(ev, files, (out) => {
        const dt = new DataTransfer();
        out.forEach((f) => dt.items.add(f));
        redispatch(ev.target, new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true, composed: true }));
      });
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
    const items = describe(c);
    const base = { entities: c, chars: text.length, trigger: "paste" };

    if (config.mode === "block") {
      send({ ...base, action: "blocked" });
      dialog({ title: "Yapıştırma engellendi", items, buttons: [{ label: "Tamam", primary: true, cancel: true }],
               message: "Kurum politikası gereği kişisel veri, sır ya da kurum bilgisi içeren metin AI sitelerine yapıştırılamaz." });
      return;
    }
    dialog({
      title: "Hassas veri tespit edildi",
      message: "Yapıştırdığınız metin şunları içeriyor. Maskeleyerek yapıştırırsanız değerlerin yerine [TCKN_1] gibi yer tutucular gider.",
      items,
      buttons: [
        { label: "Vazgeç", cancel: true, onClick: () => send({ ...base, action: "cancelled" }) },
        { label: "Yine de yapıştır", onClick: () => {
          allow(text, findings); insert(target, text); send({ ...base, action: "allowed_override" }); } },
        { label: "Maskeleyerek yapıştır", primary: true,
          onClick: () => { insert(target, D.mask(text).text); send({ ...base, action: "masked" }); } },
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
      const masked = new File([D.mask(text).text], f.name, { type: f.type || "text/plain", lastModified: f.lastModified });
      hits.push({ file: f, findings, masked });
      return f;
    }));
    const blockedUnscannable = config.unscannableFiles === "block" ? unscannable : [];
    if (!hits.length && !blockedUnscannable.length) { onDone(files); return; }

    const c = {};
    hits.forEach((h) => counts(h.findings, c));
    const base = { entities: c, chars, trigger: "file" };
    const items = hits.map((h) => `${h.file.name}: ${describe(counts(h.findings)).join(", ")}`)
      .concat(blockedUnscannable.map((f) => `${f.name}: taranamayan dosya türü`));

    if (config.mode === "block" || blockedUnscannable.length) {
      send({ ...base, action: "blocked" });
      dialog({ title: "Dosya eklenmedi", items, buttons: [{ label: "Tamam", primary: true, cancel: true, onClick: onCancel }],
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
      buttons: [
        { label: "Vazgeç", cancel: true, onClick: () => { send({ ...base, action: "cancelled" }); onCancel(); } },
        { label: "Yine de ekle", onClick: () => { send({ ...base, action: "allowed_override" }); onDone(files); } },
        { label: "Maskeleyerek ekle", primary: true, onClick: () => { send({ ...base, action: "masked" }); onDone(maskedOut); } },
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

  document.addEventListener("paste", onPaste, true);

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
    const findings = D.analyze(text).filter((f) => !allowedValues.has(text.slice(f.start, f.end)));
    if (!findings.length) return false;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    const c = counts(findings);
    const items = describe(c);
    const base = { entities: c, chars: text.length, trigger: "send" };
    const masked = () => D.mask(text, { continueNumbering: true }).text;
    const done = () => { dialogOpen = false; };
    dialogOpen = true;

    if (config.mode === "block") {
      send({ ...base, action: "blocked" });
      dialog({ title: "Gönderim engellendi", items, message: "Kurum politikası gereği kişisel veri, sır ya da kurum bilgisi içeren mesaj " +
                 "AI sitelerine gönderilemez. Metni maskeleyip kontrol ettikten sonra tekrar gönderebilirsiniz.",
               buttons: [
                 { label: "Düzenle", cancel: true, onClick: () => { done(); composer.focus(); } },
                 { label: "Metni maskele", primary: true, onClick: () => { done(); replaceComposer(composer, masked()); } },
               ] });
      return true;
    }
    dialog({
      title: "Göndermeden önce",
      message: "Mesajınız şunları içeriyor. Maskeleyerek gönderirseniz değerlerin yerine [TCKN_1] gibi yer tutucular gider.",
      items,
      buttons: [
        { label: "Düzenle", cancel: true, onClick: () => { done(); send({ ...base, action: "cancelled" }); composer.focus(); } },
        { label: "Yine de gönder", onClick: () => {
          done(); allow(text, findings); send({ ...base, action: "allowed_override" }); resend(composer, button); } },
        { label: "Maskele ve gönder", primary: true, onClick: () => {
          done(); replaceComposer(composer, masked()); send({ ...base, action: "masked" });
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
