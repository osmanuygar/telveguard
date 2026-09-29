/*
 * AI sohbet sitelerinde yapıştırma ve gönderim koruması.
 * Metin YEREL olarak taranır (detectors.js); kişisel veri ya da sır varsa:
 *   yapıştırma: warn  -> "Maskeleyerek yapıştır" (önerilen) / "Vazgeç" / "Yine de yapıştır"
 *               block -> yapıştırma engellenir
 *   gönderim (Enter ya da gönder düğmesi; elle yazılan metin de):
 *               warn  -> "Maskele ve gönder" (önerilen) / "Düzenle" / "Yine de gönder"
 *               block -> gönderilmez; "Metni maskele" ile düzeltilip tekrar gönderilebilir
 * Telveguard'a yalnızca site, veri türü adetleri ve karar gider; metin asla gönderilmez.
 * Pencere Shadow DOM'da: sitenin CSS'i bozamaz, sitenin betikleri içeriğini okuyamaz.
 */
(function () {
  "use strict";
  const D = self.TelveguardDetectors;
  if (!D || window.__telveguardLoaded) return;
  window.__telveguardLoaded = true;

  const site = location.hostname.replace(/^www\./, "");
  let config = { mode: "warn", reportVisits: false };
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

  // Kullanıcının "yine de" dediği değerler (yalnızca bu sayfanın belleğinde; saklanmaz / gönderilmez):
  // aynı değer için gönderimde ikinci kez sorulmaz
  const allowedValues = new Set();
  const allow = (text, findings) => findings.forEach((f) => allowedValues.add(text.slice(f.start, f.end)));

  function counts(findings) {
    const c = {};
    for (const f of findings) c[f.entity] = (c[f.entity] || 0) + 1;
    return c;
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
    const text = ev.clipboardData && ev.clipboardData.getData("text/plain");
    if (!text) return;
    const findings = D.analyze(text);
    if (!findings.length) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    const target = ev.target;
    const c = counts(findings);
    const items = Object.entries(c).map(([e, n]) => `${D.label(e)}${n > 1 ? ` (${n})` : ""}`);
    const base = { entities: c, chars: text.length, trigger: "paste" };

    if (config.mode === "block") {
      send({ ...base, action: "blocked" });
      dialog({ title: "Yapıştırma engellendi", items, buttons: [{ label: "Tamam", primary: true, cancel: true }],
               message: "Kurum politikası gereği kişisel veri ya da sır içeren metin AI sitelerine yapıştırılamaz." });
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
    const items = Object.entries(c).map(([e, n]) => `${D.label(e)}${n > 1 ? ` (${n})` : ""}`);
    const base = { entities: c, chars: text.length, trigger: "send" };
    const masked = () => D.mask(text, { continueNumbering: true }).text;
    const done = () => { dialogOpen = false; };
    dialogOpen = true;

    if (config.mode === "block") {
      send({ ...base, action: "blocked" });
      dialog({ title: "Gönderim engellendi", items, message: "Kurum politikası gereği kişisel veri ya da sır içeren mesaj " +
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
