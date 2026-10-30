/*
 * Eklenti pencereleri gerçek tarayıcıda (paste.test.html; content.js + detectors.js).
 *   cd extension/tests && npm ci && npx playwright install chromium firefox
 *   BROWSER=chromium node browser.test.js     (firefox da olur; Chrome için CHANNEL=chrome)
 */
"use strict";
const assert = require("assert");
const fs = require("fs");
const http = require("http");
const path = require("path");
const playwright = require("playwright");

const ROOT = path.join(__dirname, "..");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8" };
const NAME = process.env.BROWSER || "chromium";
const SECRET = ["ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join("");   // kaynakta parça parça (secret scanning)

const server = http.createServer((req, res) => {
  const file = path.join(ROOT, decodeURIComponent(new URL(req.url, "http://x").pathname));
  if (!file.startsWith(ROOT) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "text/plain" });
  res.end(fs.readFileSync(file));
});

// Değerler çerçevede: test sayfasında aynı köken, içine bakılabilir (gerçek sitede bakılamaz)
const state = async (p) => {
  await p.waitForFunction(() => { const d = window.__telveguardDialog; return d && d.previews.every((x) => x.ready); });
  return p.evaluate(() => {
    const d = window.__telveguardDialog;
    const docs = d.previews.map((x) => x.el.contentDocument);
    const all = (q) => docs.flatMap((x) => [...x.querySelectorAll(q)]);
    return { text: d.root.textContent + docs.map((x) => x.body.textContent).join(" "), dialogText: d.root.textContent,
             boxes: all("input[type=checkbox]").length, marks: all("mark").map((m) => m.textContent), imgs: all("img").length,
             ph: all(".ph").map((x) => x.textContent), disabled: d.buttons.filter((b) => b.disabled).map((b) => b.textContent) };
  });
};
const uncheck = async (p, i) => {
  await state(p);
  await p.evaluate((n) => window.__telveguardDialog.previews[0].el.contentDocument.querySelectorAll("input[type=checkbox]")[n].click(), i);
  await p.waitForTimeout(50);
};
const press = (p, label) => p.evaluate((l) => window.dialogButton(l), label);
const paste = (p, text, id = "ta") => p.evaluate(([t, i]) => window.pasteInto(document.getElementById(i), t), [text, id]);
const sendText = (p, text) => p.evaluate((t) => { const ta = document.getElementById("chat-ta"); window.typeInto(ta, t); window.pressEnter(ta); }, text);
const events = (p) => p.evaluate(() => window.__sent.filter((m) => m.type === "event" && m.event.action !== "visit").map((m) => m.event));
const showReply = (p, text) => p.evaluate((t) => { document.getElementById("reply").textContent = t; }, text);
/** Cevaptaki metnin ortasına fare: yer tutucunun ekrandaki konumu Range ile bulunur. */
const hover = async (p, needle) => {
  const at = await p.evaluate((n) => {
    const node = document.getElementById("reply").firstChild;
    const r = document.createRange();
    const i = node.data.indexOf(n);
    r.setStart(node, i); r.setEnd(node, i + n.length);
    const b = r.getBoundingClientRect();
    return { x: b.left + b.width / 2, y: b.top + b.height / 2 };
  }, needle);
  await p.mouse.move(at.x, at.y);
  await p.waitForTimeout(200);
};
const tip = (p) => p.evaluate(() => { const t = window.__telveguardReveal?.tip; return t && !t.hidden ? t.contentDocument.body.textContent.trim() : null; });
const maskAndSend = async (p, text) => {
  await sendText(p, text);
  const n = await p.evaluate(() => window.__messages.length);
  await press(p, "Maskele ve gönder");
  await p.waitForFunction((c) => window.__messages.length === c + 1, n);
  await p.waitForTimeout(1600);   // yeniden gönderim penceresi kapansın
};

const TESTS = {
  "yapıştırma: değerler, maskeli metin, sır kısaltılır": async (p) => {
    await paste(p, `Mail a@ornek.com ve b@ornek.com, anahtar ${SECRET} son`);
    const s = await state(p);
    assert.equal(s.boxes, 3);
    assert.deepEqual(s.marks.slice(0, 2), ["[EMAIL_ADDRESS_1]", "[EMAIL_ADDRESS_2]"]);
    assert.ok(!s.text.includes(SECRET), "sırrın tamamı pencerede");
    assert.ok(s.text.includes("ghp_…") && s.text.includes("a@ornek.com"));
  },
  "kısmi maskeleme: numara yeniden verilir, olaylar ayrı": async (p) => {
    await paste(p, "Mail a@ornek.com ve b@ornek.com tekrar a@ornek.com");
    await uncheck(p, 0);
    assert.deepEqual((await state(p)).ph, ["maskelenmez", "→ [EMAIL_ADDRESS_1]"]);
    await press(p, "Maskeleyerek yapıştır");
    assert.equal(await p.inputValue("#ta"), "Mail a@ornek.com ve [EMAIL_ADDRESS_1] tekrar a@ornek.com");
    const ev = await events(p);
    assert.deepEqual(ev.map((e) => [e.action, e.justification, e.entities.EMAIL_ADDRESS]),
      [["masked", undefined, 1], ["allowed_override", "false_positive", 2]]);
    assert.ok(!JSON.stringify(ev).includes("ornek.com"), "olayda değer var");
  },
  "hepsi kaldırılınca maskele düğmesi kapanır, geri açılır": async (p) => {
    await paste(p, "Mail a@ornek.com");
    await uncheck(p, 0);
    assert.deepEqual((await state(p)).disabled, ["Maskeleyerek yapıştır"]);
    await uncheck(p, 0);
    assert.deepEqual((await state(p)).disabled, []);
  },
  "gönderim: kısmi maskeleme gider, bırakılan değer yeniden sorulmaz": async (p) => {
    await sendText(p, "Mail a@ornek.com ve b@ornek.com");
    await uncheck(p, 0);
    await press(p, "Maskele ve gönder");
    await p.waitForFunction(() => window.__messages.length === 1);
    assert.equal(await p.evaluate(() => window.__messages[0]), "Mail a@ornek.com ve [EMAIL_ADDRESS_1]");
    await p.waitForTimeout(1600);
    await sendText(p, "Yine a@ornek.com");
    assert.equal(await p.evaluate(() => window.dialogOpen()), false);
    assert.equal(await p.evaluate(() => window.__messages[1]), "Yine a@ornek.com");
  },
  "gönderim: 'yine de' denen değer sonraki maskelemede korunur": async (p) => {
    await sendText(p, "a@ornek.com");
    await press(p, "Yine de gönder");
    await p.waitForFunction(() => window.__messages.length === 1);
    await p.waitForTimeout(1600);
    await sendText(p, "a@ornek.com ve b@ornek.com");
    assert.equal((await state(p)).boxes, 1);
    await press(p, "Maskele ve gönder");
    await p.waitForFunction(() => window.__messages.length === 2);
    assert.equal(await p.evaluate(() => window.__messages[1]), "a@ornek.com ve [EMAIL_ADDRESS_1]");
  },
  "engelle: salt okunur önizleme, Esc hata vermez": async (p) => {
    await paste(p, "Mail a@ornek.com");
    const s = await state(p);
    assert.equal(s.boxes, 0);
    assert.deepEqual(s.marks, ["[EMAIL_ADDRESS_1]"]);
    await p.keyboard.press("Escape");
    assert.equal(await p.evaluate(() => window.dialogOpen()), false);
    assert.equal(await p.inputValue("#ta"), "");
  },
  "engelle gönderim: metni maskele": async (p) => {
    await sendText(p, "Mail a@ornek.com");
    assert.equal((await state(p)).boxes, 0);
    await press(p, "Metni maskele");
    assert.equal(await p.inputValue("#chat-ta"), "Mail [EMAIL_ADDRESS_1]");
  },
  "dosya sürükleme: salt okunur önizleme, maskeli kopya": async (p) => {
    await p.evaluate(() => window.dropFiles(document.getElementById("drop"), [window.makeFile("liste.csv", "ad,mail\nAli,a@ornek.com\n", "text/csv")]));
    await p.waitForFunction(() => window.dialogOpen());
    const s = await state(p);
    assert.equal(s.boxes, 0);
    assert.ok(s.text.includes("liste.csv"));
    await press(p, "Maskeleyerek ekle");
    await p.waitForFunction(() => window.__uploads.length === 1);
    assert.equal(await p.evaluate(() => window.__uploads[0].text), "ad,mail\nAli,[EMAIL_ADDRESS_1]\n");
  },
  "dosya yapıştırma: maskeli kopya siteye ulaşır": async (p) => {
    await p.evaluate(() => window.pasteFiles(document.getElementById("chat-ta"), [window.makeFile("liste.csv", "a@ornek.com\n", "text/csv")]));
    await p.waitForFunction(() => window.dialogOpen());
    await press(p, "Maskeleyerek ekle");
    await p.waitForFunction(() => window.__uploads.length === 1);
    assert.equal(await p.evaluate(() => window.__uploads[0].text), "[EMAIL_ADDRESS_1]\n");
  },
  "metindeki HTML yorumlanmaz": async (p) => {
    await paste(p, "<img src=x onerror='window.__xss=1'> a@ornek.com");
    await p.waitForTimeout(100);
    assert.equal((await state(p)).imgs, 0);
    assert.equal(await p.evaluate(() => window.__xss), undefined);
  },
  "klavye: Tab işarete ulaşır, Boşluk kaldırır": async (p) => {
    await paste(p, "Mail a@ornek.com");
    let hit = false;
    for (let i = 0; i < 6 && !hit; i++) {
      await p.keyboard.press("Tab");
      hit = await p.evaluate(() => window.__telveguardDialog.previews[0].el.contentDocument.activeElement?.type === "checkbox");
    }
    assert.ok(hit, "Tab işarete ulaşmadı");
    await p.keyboard.press("Space");
    await p.waitForTimeout(50);
    assert.deepEqual((await state(p)).ph, ["maskelenmez"]);
  },
  "çok değer: 30 satır sınırı, sınır dışı değerler de maskelenir": async (p) => {
    await p.evaluate(() => window.pasteInto(document.getElementById("ta"),
      Array.from({ length: 2000 }, (_, i) => `satir ${i} kisi${i}@ornek.com`).join("\n")));
    assert.equal((await state(p)).boxes, 30);
    await uncheck(p, 0);
    await press(p, "Maskeleyerek yapıştır");
    const v = await p.inputValue("#ta");
    assert.ok(v.includes("kisi0@ornek.com") && !v.includes("kisi1999@ornek.com"));
  },
  "numaralar mesajlar arası ortak": async (p) => {
    await maskAndSend(p, "a@ornek.com");
    await maskAndSend(p, "b@ornek.com ve a@ornek.com");
    assert.equal(await p.evaluate(() => window.__messages[1]), "[EMAIL_ADDRESS_2] ve [EMAIL_ADDRESS_1]");
  },
  "geri açma: ipucu doğru değeri gösterir, DOM'a yazılmaz": async (p) => {
    await maskAndSend(p, "a@ornek.com");
    await maskAndSend(p, "b@ornek.com");
    await showReply(p, "Sonuç: [EMAIL_ADDRESS_2] ve bilinmeyen [TCKN_9] burada");
    await hover(p, "[EMAIL_ADDRESS_2]");
    assert.equal(await tip(p), "E-posta: b@ornek.com");
    const r = await p.evaluate(() => { const b = window.__telveguardReveal.tip.getBoundingClientRect(); return [b.width, b.height]; });
    assert.ok(r[0] > 40 && r[0] < 360 && r[1] > 10, "ipucu boyutu: " + r);
    await hover(p, "[TCKN_9]");
    assert.equal(await tip(p), null, "bilinmeyen yer tutucu");
    await hover(p, "Sonuç");
    assert.equal(await tip(p), null);
    const light = await p.evaluate(() => document.documentElement.outerHTML + document.body.innerText);
    assert.ok(!light.includes("b@ornek.com"), "değer sayfanın DOM'unda");
  },
  "geri açma: sır ipucunda kısaltılır": async (p) => {
    await maskAndSend(p, `anahtar ${SECRET}`);
    await showReply(p, "[SECRET_GITHUB_TOKEN_1] kullan");
    await hover(p, "[SECRET_GITHUB_TOKEN_1]");
    assert.equal(await tip(p), "Sır: github token: ghp_…");
  },
  "geri açma: seçili metin aslıyla kopyalanır": async (p) => {
    await maskAndSend(p, "a@ornek.com");
    await showReply(p, "Yanıt [EMAIL_ADDRESS_1] tamam");
    await p.evaluate(() => { window.__copied = null; navigator.clipboard.writeText = async (t) => { window.__copied = t; }; });
    await p.click("#reply", { clickCount: 3 });
    await p.waitForTimeout(50);
    assert.equal(await p.evaluate(() => window.__telveguardReveal.copy.hidden), false);
    const b = await p.evaluate(() => { const r = window.__telveguardReveal.copy.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; });
    await p.mouse.click(b.x, b.y);
    await p.waitForTimeout(50);
    assert.equal((await p.evaluate(() => window.__copied)).trim(), "Yanıt a@ornek.com tamam");
  },
  "yapılandırma gelmeden: 'yine de' çıkmaz (ilk kurulum)": async (p) => {
    await paste(p, "Mail a@ornek.com");
    assert.ok((await state(p)).text.includes("Yapıştırma engellendi"));
  },
  "yapılandırma gelmeden: saklanan mod hemen geçerli (warn)": async (p) => {
    await paste(p, "Mail a@ornek.com");
    assert.ok((await state(p)).text.includes("Yine de yapıştır"));
  },
  "yapılandırma gelmeden: saklanan mod hemen geçerli (block)": async (p) => {
    await paste(p, "Mail a@ornek.com");
    assert.ok((await state(p)).text.includes("Yapıştırma engellendi"));
  },
  "güncel yapılandırma saklananı ezer": async (p) => {
    await paste(p, "Mail a@ornek.com");
    assert.ok((await state(p)).text.includes("Yapıştırma engellendi"));
  },
  "güvenlik: pencerede ham değer yok, yalnızca çerçevede": async (p) => {
    await paste(p, "Mail a@ornek.com");
    const s = await state(p);
    assert.ok(s.text.includes("a@ornek.com"), "çerçevede olmalı");
    const seen = await p.evaluate(() => { const d = window.__telveguardDialog, f = d.previews[0].el; return { h: f.getBoundingClientRect().height, v: getComputedStyle(f).visibility, ul: d.root.querySelector("ul")?.hidden }; });
    assert.ok(seen.h > 30 && seen.v === "visible", "çerçeve görünmüyor: " + JSON.stringify(seen));
    assert.equal(seen.ul, true, "çerçeve açıkken özet gizli");
    assert.ok(!s.dialogText.includes("a@ornek.com"), "pencerede değer var");
    assert.ok(!(await p.evaluate(() => window.__telveguardDialog.root.querySelector(".box").textContent)).includes("ornek"));
  },
  "güvenlik: çerçeve açılmazsa tür ve adetle çalışır, hepsi maskelenir": async (p) => {
    await paste(p, "Mail a@ornek.com");
    await p.waitForTimeout(150);
    const t = await p.evaluate(() => window.__telveguardDialog.root.textContent);
    assert.ok(t.includes("E-posta") && !t.includes("a@ornek.com"));
    await press(p, "Maskeleyerek yapıştır");
    assert.equal(await p.inputValue("#ta"), "Mail [EMAIL_ADDRESS_1]");
  },
  "güvenlik: sahte mousemove ipucunu açmaz": async (p) => {
    await maskAndSend(p, "a@ornek.com");
    await showReply(p, "[EMAIL_ADDRESS_1]");
    await p.evaluate(() => {
      const r = document.createRange(); r.selectNodeContents(document.getElementById("reply")); const b = r.getBoundingClientRect();
      document.body.dispatchEvent(new MouseEvent("mousemove", { clientX: b.left + 5, clientY: b.top + b.height / 2, bubbles: true }));
    });
    await p.waitForTimeout(200);
    assert.equal(await tip(p), null);
  },
  "güvenlik: kopyalama düğmesi varsayılan kapalı": async (p) => {
    await maskAndSend(p, "a@ornek.com");
    await showReply(p, "[EMAIL_ADDRESS_1]");
    await p.click("#reply", { clickCount: 3 });
    await p.waitForTimeout(50);
    assert.equal(await p.evaluate(() => window.__telveguardReveal.copy.hidden), true);
  },
  "güvenlik: depoya yazılan mod uygulanmaz, servis çalışanı sorulur": async (p) => {
    await p.evaluate(() => window.__storageChanged({ telveguardConfig: { newValue: { mode: "warn" } } }, "local"));
    await paste(p, "Mail a@ornek.com");
    assert.ok((await state(p)).text.includes("Yapıştırma engellendi"));
  },
  "güvenlik: engelle modunda 'yine de' listesi geçmez": async (p) => {
    await p.evaluate(() => { const ta = document.getElementById("chat-ta"); window.typeInto(ta, "a@ornek.com"); window.pressEnter(ta); });
    assert.ok((await state(p)).text.includes("Gönderim engellendi"));
  },
  "güvenlik: sitenin window dinleyicisi hassas yapıştırmayı görmez, temizi görür": async (p) => {
    await p.evaluate(() => {
      window.__pageSaw = [];
      window.addEventListener("paste", (e) => window.__pageSaw.push(e.clipboardData.getData("text/plain")), true);
    });
    await paste(p, "Mail a@ornek.com");
    assert.deepEqual(await p.evaluate(() => window.__pageSaw), []);
    await press(p, "Vazgeç");
    await paste(p, "temiz metin");
    assert.deepEqual(await p.evaluate(() => window.__pageSaw), ["temiz metin"]);
  },
  "çerçeve açılamazsa bildirilir, olaylar işaretlenir": async (p) => {
    await paste(p, "Mail a@ornek.com");
    await p.waitForFunction(() => window.__sent.some((m) => m.type === "previewStatus" && m.ok === false), null, { timeout: 5000 });
    await press(p, "Maskeleyerek yapıştır");
    const ev = await events(p);
    assert.equal(ev[ev.length - 1].preview_unavailable, true);
  },
  "çerçeve açılınca bildirilir, olaylar işaretlenmez": async (p) => {
    await paste(p, "Mail a@ornek.com");
    await state(p);
    assert.ok(await p.evaluate(() => window.__sent.some((m) => m.type === "previewStatus" && m.ok === true)));
    await press(p, "Maskeleyerek yapıştır");
    assert.equal((await events(p)).pop().preview_unavailable, undefined);
  },
  "MDM geri açmayı kapatınca ipucu açık sayfada da kapanır": async (p) => {
    await maskAndSend(p, "a@ornek.com");
    await showReply(p, "Sonuç: [EMAIL_ADDRESS_1] burada");
    await hover(p, "[EMAIL_ADDRESS_1]");
    assert.equal(await tip(p), "E-posta: a@ornek.com");
    await p.mouse.move(1, 1);
    await p.evaluate(() => { window.__configOverride = { revealPlaceholders: false }; window.__storageChanged({ telveguardConfig: { newValue: {} } }, "local"); });
    await hover(p, "[EMAIL_ADDRESS_1]");
    assert.equal(await tip(p), null);
  },
  "geri açma: reddedilen maskelemede eşleme tutulmaz": async (p) => {
    await sendText(p, "a@ornek.com");
    await press(p, "Düzenle");
    assert.equal(await p.evaluate(() => window.__telveguardReveal), undefined);
  },
};

const QUERY = { "engelle: salt okunur önizleme, Esc hata vermez": "?mode=block", "engelle gönderim: metni maskele": "?mode=block",
                "gönderim: 'yine de' denen değer sonraki maskelemede korunur": "?justify=0",
                "yapılandırma gelmeden: 'yine de' çıkmaz (ilk kurulum)": "?late=1",
                "yapılandırma gelmeden: saklanan mod hemen geçerli (warn)": "?late=1&cached=warn",
                "yapılandırma gelmeden: saklanan mod hemen geçerli (block)": "?late=1&cached=block",
                "güncel yapılandırma saklananı ezer": "?cached=warn&mode=block",
                "çerçeve açılamazsa bildirilir, olaylar işaretlenir": "?noframe=1",
                "geri açma: seçili metin aslıyla kopyalanır": "?copy=1",
                "güvenlik: çerçeve açılmazsa tür ve adetle çalışır, hepsi maskelenir": "?noframe=1",
                "güvenlik: depoya yazılan mod uygulanmaz, servis çalışanı sorulur": "?mode=block",
                "güvenlik: engelle modunda 'yine de' listesi geçmez": "?mode=block" };

(async () => {
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${server.address().port}/tests/paste.test.html`;
  const browser = await playwright[NAME].launch({ channel: process.env.CHANNEL || undefined });
  let failed = 0;
  for (const [name, fn] of Object.entries(TESTS)) {
    const page = await browser.newPage({ viewport: { width: 1000, height: 900 } });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    try {
      await page.goto(base + (QUERY[name] || ""));
      await fn(page);
      assert.deepEqual(errors, [], "sayfa hatası: " + errors.join(" | "));
      console.log(`ok    ${name}`);
    } catch (e) {
      failed++;
      console.log(`HATA  ${name}\n      ${String(e.message).split("\n").slice(0, 3).join(" ")}`);
    }
    await page.close();
  }
  await browser.close();
  server.close();
  console.log(`${NAME}: ${Object.keys(TESTS).length - failed} / ${Object.keys(TESTS).length}`);
  process.exit(failed ? 1 : 0);
})();
