/*
 * Servis çalışanı: MDM yapılandırmasını okur, content script'ten gelen olayları Telveguard'a gönderir.
 * Olaylarda metin YOK: site, veri türü adetleri, karar. Gönderilemeyen olaylar yerel kuyrukta
 * bekler (en fazla 500) ve 5 dakikada bir yeniden denenir; servis çalışanı kapansa da kaybolmaz.
 * Kurumsal sözlük saatte bir gateway'den çekilir (terimler özet olarak; ETag ile değişmediyse inmez)
 * ve chrome.storage.local'da durur; content script oradan okur.
 */
"use strict";

const DEFAULTS = { telveguardUrl: "", reportToken: "", mode: "warn", user: "", team: "default", reportVisits: false,
  unscannableFiles: "allow", requireJustification: true, sanctionedAiUrl: "", sanctionedAiName: "", showBanner: true,
  revealPlaceholders: true, revealCopy: false };
// Onaylı AI aracı yalnızca https (yerel geliştirme: http://localhost); başka şema (javascript: vb.) açılmaz
const safeUrl = (u) => /^https:\/\/|^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(u || "") ? u : "";
const QUEUE_KEY = "telveguardQueue";
const DICT_KEY = "telveguardDictionary";
const CONFIG_KEY = "telveguardConfig";
const STATS_KEY = "telveguardStats";      // bu haftanın yerel sayaçları (adet; değer yok, gönderilmez)
const PREVIEW_KEY = "telveguardPreviewFailed";   // önizleme çerçevesinin açılamadığı siteler (yalnızca bu cihazda)
const SYNC_KEY = "telveguardLastSync";    // gateway'e son başarılı erişim
const MAX_QUEUE = 500;
const VERSION = chrome.runtime.getManifest().version;

// İçerik betiğinin gördüğü alanlar (token ve adres yok): sitelerin açılışında hemen okunsun diye saklanır
function publicConfig(c) {
  return { mode: c.mode, reportVisits: !!c.reportVisits, reporting: !!c.telveguardUrl,
           unscannableFiles: c.unscannableFiles === "block" ? "block" : "allow",
           requireJustification: c.requireJustification !== false,
           sanctionedAiUrl: safeUrl(c.sanctionedAiUrl), sanctionedAiName: c.sanctionedAiName || "",
           showBanner: c.showBanner !== false, revealPlaceholders: c.revealPlaceholders !== false, revealCopy: c.revealCopy === true };
}
const saveConfig = (c) => chrome.storage.local.set({ [CONFIG_KEY]: publicConfig(c) });

async function config() {
  let managed = {};
  try { managed = await chrome.storage.managed.get(null); } catch { /* okunamadı: aşağıda son bilinen */ }
  if (Object.keys(managed).length) {
    const c = { ...DEFAULTS, ...managed };
    await saveConfig(c);
    return c;
  }
  // Boş ya da okunamadı: tarayıcı açılışında politika gecikebilir, son bilinen mod korunur (block -> warn düşmesin).
  // Politika gerçekten kaldırılırsa storage.onChanged kaydı günceller. Hiç kayıt yoksa: yönetilmeyen kurulum.
  const known = (await chrome.storage.local.get(CONFIG_KEY))[CONFIG_KEY];
  if (!known) await saveConfig(DEFAULTS);   // yönetilmeyen kurulum her soğuk başlangıçta sıkı moda düşmesin
  return { ...DEFAULTS, ...known };
}

// Kayıtta görünecek kişi: MDM'deki user (kurum belirler) > Chrome'da oturum açmış profilin e-postası
// (identity.email izni; senkronizasyon kapalı olsa da) > "unknown". İkisi de beyandır, JWT gibi
// doğrulanmaz; gateway biçimini yine denetler.
const USER_RE = /^[\w.@+-]{1,200}$/u;
async function whoAmI(cfg) {
  if (cfg.user) return { user: cfg.user, source: "mdm" };
  try {
    const info = await chrome.identity.getProfileUserInfo({ accountStatus: "ANY" });
    if (info?.email && USER_RE.test(info.email)) return { user: info.email, source: "chrome" };
  } catch { /* izin yok / eski Chrome */ }
  return { user: "unknown", source: "none" };
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
      await chrome.storage.local.set({ [QUEUE_KEY]: (await readQueue()).slice(batch.length), [SYNC_KEY]: Date.now() });
      if (queue.length > batch.length) await flush();
    }
  } catch {
    /* ağ yok: alarmda yeniden denenir */
  }
}

async function refreshDictionary() {
  const cfg = await config();
  if (!cfg.telveguardUrl || !cfg.reportToken) return;
  const current = (await chrome.storage.local.get(DICT_KEY))[DICT_KEY];
  const headers = { Authorization: `Bearer ${cfg.reportToken}` };
  if (current && current.version) headers["If-None-Match"] = `"${current.version}"`;
  try {
    const r = await fetch(`${cfg.telveguardUrl.replace(/\/$/, "")}/v1/shadow-ai/dictionary`, { headers, cache: "no-store" });
    if (r.status === 304) {
      await chrome.storage.local.set({ [DICT_KEY]: { ...current, checked_at: Date.now() }, [SYNC_KEY]: Date.now() });
    } else if (r.ok) {
      await chrome.storage.local.set({ [DICT_KEY]: { ...(await r.json()), checked_at: Date.now() }, [SYNC_KEY]: Date.now() });
    }
    // Diğer durumlar (eski gateway: 404, ağ hatası): eldeki sözlükle devam
  } catch {
    /* ağ yok: bir sonraki alarmda yeniden denenir */
  }
}

async function enqueue(event) {
  const cfg = await config();
  const { user } = await whoAmI(cfg);
  const full = { ...event, user, team: cfg.team, extension_version: VERSION };
  const queue = (await readQueue()).concat([full]).slice(-MAX_QUEUE);
  await chrome.storage.local.set({ [QUEUE_KEY]: queue });
  await flush();
}

// Haftanın başı (pazartesi, yerel saat): sayaçlar hafta değişince sıfırlanır
function weekStart(now = new Date()) {
  const d = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  d.setDate(d.getDate() - ((d.getDay() + 6) % 7));
  return d.getTime();
}

// Sayaç ve rozet oku-yaz yapar: olaylar sırayla işlensin (kısmi maskeleme art arda iki olay yollar)
let tally = Promise.resolve();
function countEvent(event, tabId) {
  const n = Object.values(event.entities || {}).reduce((a, b) => a + b, 0);
  if (!["masked", "blocked", "allowed_override"].includes(event.action) || !n) return;
  tally = tally.then(async () => {
    const week = weekStart();
    const saved = (await chrome.storage.local.get(STATS_KEY))[STATS_KEY];
    const s = saved && saved.week === week ? saved : { week, masked: 0, blocked: 0, allowed_override: 0 };
    s[event.action] += n;
    await chrome.storage.local.set({ [STATS_KEY]: s });
    if (tabId !== undefined) {   // simgede bu sekmede yakalanan değer sayısı; sekme kapanınca silinir
      const shown = Number(await chrome.action.getBadgeText({ tabId })) || 0;
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#8a4b1f" });
      await chrome.action.setBadgeText({ tabId, text: String(shown + n) });
    }
  }).catch(() => { /* sekme kapanmış: sayaç önemsiz */ });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "getConfig") {
    config().then((c) => sendResponse(publicConfig(c)));
    return true;
  }
  if (msg?.type === "whoami") {
    config().then(async (c) => sendResponse({ ...(await whoAmI(c)), team: c.team }));
    return true;
  }
  if (msg?.type === "previewStatus" && typeof msg.site === "string") {
    tally = tally.then(async () => {
      const failed = (await chrome.storage.local.get(PREVIEW_KEY))[PREVIEW_KEY] || {};
      if (msg.ok) delete failed[msg.site]; else failed[msg.site] = Date.now();
      await chrome.storage.local.set({ [PREVIEW_KEY]: failed });
    }).catch(() => {});
  }
  if (msg?.type === "event" && msg.event) {
    enqueue(msg.event);
    countEvent(msg.event, sender.tab && sender.tab.id);
  }
  return false;
});

chrome.alarms.create("telveguard-flush", { periodInMinutes: 5 });
chrome.alarms.create("telveguard-dictionary", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "telveguard-flush") flush();
  if (a.name === "telveguard-dictionary") refreshDictionary();
});
chrome.runtime.onInstalled.addListener(refreshDictionary);
chrome.runtime.onStartup.addListener(refreshDictionary);
// MDM yapılandırması sonradan gelirse (ilk kurulumda politika gecikebilir) hemen çek
// Kayıt da güncellenir: açık sekmeler yeni modu hemen alır, politika kaldırıldıysa eski mod kalmaz
chrome.storage.onChanged.addListener(async (_changes, area) => {
  if (area !== "managed") return;
  await saveConfig({ ...DEFAULTS, ...(await chrome.storage.managed.get(null)) });
  refreshDictionary();
});
