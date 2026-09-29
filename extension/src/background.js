/*
 * Servis çalışanı: MDM yapılandırmasını okur, content script'ten gelen olayları Telveguard'a gönderir.
 * Olaylarda metin YOK: site, veri türü adetleri, karar. Gönderilemeyen olaylar yerel kuyrukta
 * bekler (en fazla 500) ve 5 dakikada bir yeniden denenir; servis çalışanı kapansa da kaybolmaz.
 */
"use strict";

const DEFAULTS = { telveguardUrl: "", reportToken: "", mode: "warn", user: "unknown", team: "default", reportVisits: false };
const QUEUE_KEY = "telveguardQueue";
const MAX_QUEUE = 500;
const VERSION = chrome.runtime.getManifest().version;

async function config() {
  try {
    return { ...DEFAULTS, ...(await chrome.storage.managed.get(null)) };
  } catch {
    return { ...DEFAULTS };   // yönetilmeyen kurulum (geliştirme): yalnızca yerel koruma
  }
}

async function readQueue() {
  return (await chrome.storage.local.get(QUEUE_KEY))[QUEUE_KEY] || [];
}

async function flush() {
  const cfg = await config();
  const queue = await readQueue();
  if (!queue.length || !cfg.telveguardUrl || !cfg.reportToken) return;
  const batch = queue.slice(0, 100);
  try {
    const r = await fetch(`${cfg.telveguardUrl.replace(/\/$/, "")}/v1/shadow-ai/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${cfg.reportToken}` },
      body: JSON.stringify({ events: batch }),
    });
    // 400: geçersiz olay tekrar denense de geçmez -> kuyruktan at; diğer hatalarda sakla
    if (r.ok || r.status === 400) {
      await chrome.storage.local.set({ [QUEUE_KEY]: (await readQueue()).slice(batch.length) });
      if (queue.length > batch.length) await flush();
    }
  } catch {
    /* ağ yok: alarmda yeniden denenir */
  }
}

async function enqueue(event) {
  const cfg = await config();
  const full = { ...event, user: cfg.user, team: cfg.team, extension_version: VERSION };
  const queue = (await readQueue()).concat([full]).slice(-MAX_QUEUE);
  await chrome.storage.local.set({ [QUEUE_KEY]: queue });
  await flush();
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "getConfig") {
    config().then((c) => sendResponse({ mode: c.mode, reportVisits: !!c.reportVisits, reporting: !!c.telveguardUrl }));
    return true;
  }
  if (msg?.type === "event" && msg.event) {
    enqueue(msg.event);
  }
  return false;
});

chrome.alarms.create("telveguard-flush", { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "telveguard-flush") flush(); });
