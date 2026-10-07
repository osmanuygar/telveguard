"use strict";
chrome.runtime.sendMessage({ type: "getConfig" }, (c) => {
  document.getElementById("mode").textContent = c && c.mode === "block" ? "Engelle" : "Uyar ve maskele";
  document.getElementById("reporting").textContent = c && c.reporting ? "Açık" : "Kapalı (yalnızca yerel koruma)";
});
chrome.storage.local.get(["telveguardQueue", "telveguardDictionary"], (v) => {
  document.getElementById("queue").textContent = String((v.telveguardQueue || []).length);
  const d = v.telveguardDictionary;
  const n = d ? (d.terms || []).reduce((sum, t) => sum + t.hashes.length, 0) + (d.patterns || []).length : 0;
  document.getElementById("dictionary").textContent = d
    ? `${n} terim · ${new Date(d.checked_at).toLocaleString("tr-TR", { dateStyle: "short", timeStyle: "short" })}`
    : "Yok";
});
