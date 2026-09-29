"use strict";
chrome.runtime.sendMessage({ type: "getConfig" }, (c) => {
  document.getElementById("mode").textContent = c && c.mode === "block" ? "Engelle" : "Uyar ve maskele";
  document.getElementById("reporting").textContent = c && c.reporting ? "Açık" : "Kapalı (yalnızca yerel koruma)";
});
chrome.storage.local.get("telveguardQueue", (v) => {
  document.getElementById("queue").textContent = String((v.telveguardQueue || []).length);
});
