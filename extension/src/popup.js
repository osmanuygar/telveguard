"use strict";
document.getElementById("version").textContent = chrome.runtime.getManifest().version;
const showConfig = (c) => {
  document.getElementById("mode").textContent = c && c.mode === "block" ? "Engelle" : "Uyar ve maskele";
  document.getElementById("reporting").textContent = c && c.reporting ? "Açık" : "Kapalı (yalnızca yerel koruma)";
  document.getElementById("sanctioned").textContent = c && c.sanctionedAiUrl ? (c.sanctionedAiName || "Tanımlı") : "Tanımlı değil";
};
// Önce saklanan (hemen), sonra servis çalışanının güncel cevabı
chrome.storage.local.get("telveguardConfig", (v) => { if (v.telveguardConfig) showConfig(v.telveguardConfig); });
chrome.runtime.sendMessage({ type: "getConfig" }, showConfig);
chrome.runtime.sendMessage({ type: "whoami" }, (w) => {
  if (!w) return;
  const how = { mdm: "kurum ayarı", chrome: "Chrome profili", none: "bilinmiyor" }[w.source] || "";
  document.getElementById("who").textContent = `${w.user} · ${w.team} (${how})`;
});
// Etkin sekme kapsamda mı? Manifest'teki site listesiyle karşılaştırılır
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  let host = "";
  try { host = new URL(tabs[0].url).host; } catch { /* adres yok: tarayıcı sayfası */ }
  const covered = chrome.runtime.getManifest().content_scripts[0].matches.some((m) => new URL(m.replace("/*", "/")).host === host);
  document.getElementById("page").textContent = covered ? "Korunuyor" : "Kapsam dışı";
  chrome.storage.local.get("telveguardPreviewFailed", (v) => {
    const failed = (v.telveguardPreviewFailed || {})[host.replace(/^www\./, "")];
    document.getElementById("preview").textContent = !covered ? "–" : failed ? "Açılamıyor (yalnızca tür ve adet)" : "Sorun görülmedi";
  });
});
chrome.storage.local.get(["telveguardQueue", "telveguardDictionary", "telveguardStats", "telveguardLastSync"], (v) => {
  document.getElementById("queue").textContent = String((v.telveguardQueue || []).length);
  const monday = new Date(); monday.setHours(0, 0, 0, 0); monday.setDate(monday.getDate() - ((monday.getDay() + 6) % 7));
  const s = v.telveguardStats && v.telveguardStats.week === monday.getTime() ? v.telveguardStats : null;
  document.getElementById("week").textContent = s
    ? `${s.masked} maskelendi · ${s.blocked} engellendi · ${s.allowed_override} geçti` : "Yakalanan değer yok";
  document.getElementById("sync").textContent = v.telveguardLastSync
    ? new Date(v.telveguardLastSync).toLocaleString("tr-TR", { dateStyle: "short", timeStyle: "short" }) : "Yok";
  const d = v.telveguardDictionary;
  const n = d ? (d.terms || []).reduce((sum, t) => sum + t.hashes.length, 0) + (d.patterns || []).length : 0;
  const exc = d && d.exceptions;
  const e = exc ? (exc.values || []).reduce((sum, v) => sum + v.hashes.length, 0) + (exc.patterns || []).length : 0;
  document.getElementById("dictionary").textContent = d
    ? `${n} terim${e ? ` · ${e} istisna` : ""} · ${new Date(d.checked_at).toLocaleString("tr-TR", { dateStyle: "short", timeStyle: "short" })}`
    : "Yok";
});
