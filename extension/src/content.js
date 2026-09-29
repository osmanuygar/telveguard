/*
 * AI sohbet sitelerinde yapıştırma koruması.
 * Yapıştırılan metin YEREL olarak taranır (detectors.js); kişisel veri ya da sır varsa:
 *   warn  -> "Maskeleyerek yapıştır" (önerilen) / "Vazgeç" / "Yine de yapıştır"
 *   block -> yapıştırma engellenir
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
    const base = { entities: c, chars: text.length };

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
        { label: "Yine de yapıştır", onClick: () => { insert(target, text); send({ ...base, action: "allowed_override" }); } },
        { label: "Maskeleyerek yapıştır", primary: true,
          onClick: () => { insert(target, D.mask(text).text); send({ ...base, action: "masked" }); } },
      ],
    });
  }

  document.addEventListener("paste", onPaste, true);
})();
