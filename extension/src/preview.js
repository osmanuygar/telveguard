/*
 * Hassas değerlerin gösterildiği çerçeve (önizleme ve ipucu). Kaynağı eklenti olduğu için sitenin
 * betikleri içeriğini okuyamaz; closed Shadow DOM bunu sağlamaz (window.find değeri bulur).
 * Veri yalnızca content.js'in aktardığı MessageChannel'dan gelir. Site bu sayfayı kendi çerçevesinde
 * açabilir ama yalnızca kendi yolladığını görür; kasaya erişemez. Metin yalnızca textContent ile yazılır.
 */
"use strict";
(function () {
  const root = document.getElementById("root");
  let port = null;
  let open = false;   // değerler varsayılan kapalı: pencere kısa kalsın, ekran paylaşımında değer görünmesin
  let last = null;

  const el = (tag, className, text) => {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
  };
  // İçeriğin kendi ölçüsü (belge ölçüsü çerçeveden küçük olamaz; gizli çerçeve de ölçülebilir)
  const report = () => {
    const b = (root.querySelector("#tip") || root).getBoundingClientRect();
    port.postMessage({ type: "size", width: Math.ceil(b.width), height: Math.ceil(b.height) });
  };
  const focusables = () => [...root.querySelectorAll("button, input[type=checkbox]")];

  function renderPreview(m) {
    last = m;
    const focused = focusables().indexOf(document.activeElement);
    const scroll = root.querySelector(".values")?.scrollTop || 0;
    root.textContent = "";
    if (m.caption) root.append(el("div", "caption", m.caption));
    const toggle = el("button", "toggle", open ? "▾ Değerleri gizle" : `▸ Değerleri göster (${m.count})`);
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", String(open));
    toggle.addEventListener("click", () => { open = !open; renderPreview(last); });
    root.append(toggle);
    if (!open) { restoreFocus(focused); report(); return; }
    const values = el("div", "values");
    m.rows.forEach((r, i) => {
      const row = el(m.selectable ? "label" : "div", "value");
      if (m.selectable) {
        const box = el("input");
        box.type = "checkbox";
        box.checked = r.on;
        box.setAttribute("aria-label", `${r.label} maskelensin`);
        box.addEventListener("change", () => port.postMessage({ type: "toggle", i }));
        row.append(box);
      }
      row.append(el("span", "type", r.label), el("code", "", r.value), el("span", "ph", r.ph));
      values.append(row);
    });
    root.append(values);
    values.scrollTop = scroll;
    if (m.more) root.append(el("div", "muted", m.more));
    restoreFocus(focused);
    report();
  }

  function restoreFocus(i) {
    const f = focusables();
    if (i >= 0) (f[i] || f[0]).focus();
  }

  function renderTip(m) {
    document.body.className = "tip";
    root.textContent = "";
    root.append(Object.assign(el("div", "", m.text), { id: "tip" }));
    report();
  }

  addEventListener("keydown", (e) => {
    if (!port) return;
    if (e.key === "Escape") { e.preventDefault(); port.postMessage({ type: "escape" }); }
    if (e.key === "Tab") {
      const b = focusables();
      const i = b.indexOf(document.activeElement);
      const next = i + (e.shiftKey ? -1 : 1);
      if (next >= 0 && next < b.length) { e.preventDefault(); b[next].focus(); return; }
      e.preventDefault();
      port.postMessage({ type: "leave", back: e.shiftKey });
    }
  });

  addEventListener("message", (ev) => {
    if (port || ev.data !== "telveguard-init" || !ev.ports[0]) return;
    port = ev.ports[0];
    port.onmessage = ({ data: m }) => {
      if (m.kind === "preview") renderPreview(m);
      if (m.kind === "tip") renderTip(m);
      if (m.kind === "focus") { const b = focusables(); (m.last ? b[b.length - 1] : b[0])?.focus(); }
    };
    port.postMessage({ type: "ready" });
  });
})();
