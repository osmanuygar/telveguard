/*
 * Telveguard tespit motoru - tarayıcı sürümü (telveguard_core/pii ile aynı desenler).
 * Python motoruyla tutarlılığı extension/tests/fixtures.json (Python'un ürettiği) denetler:
 *   node extension/tests/detectors.test.js
 * Metin tarayıcıdan ÇIKMAZ: bu dosya yalnızca yerel tespit ve maskeleme yapar.
 * Aynı dosya tarayıcıda (content script) ve Node'da (test) çalışır.
 */
(function (root) {
  "use strict";

  // ---------- doğrulayıcılar ----------
  const digits = (v) => v.replace(/\D/g, "").split("").map(Number);

  function isValidTckn(v) {
    const d = digits(v);
    if (d.length !== 11 || d[0] === 0) return false;
    const odd = d[0] + d[2] + d[4] + d[6] + d[8];
    const even = d[1] + d[3] + d[5] + d[7];
    const d10 = (((odd * 7) - even) % 10 + 10) % 10;   // Python % her zaman pozitif
    const sum10 = d.slice(0, 10).reduce((a, b) => a + b, 0);
    return d[9] === d10 && d[10] === sum10 % 10;
  }

  function isValidVkn(v) {
    const d = digits(v);
    if (d.length !== 10) return false;
    let total = 0;
    for (let i = 0; i < 9; i++) {
      const tmp = (d[i] + 9 - i) % 10;
      let x = (tmp * 2 ** (9 - i)) % 9;
      if (tmp !== 0 && x === 0) x = 9;
      total += x;
    }
    return (10 - (total % 10)) % 10 === d[9];
  }

  function isValidTrIban(v) {
    const s = v.replace(/\s/g, "").toUpperCase();
    if (!/^TR\d{24}$/.test(s)) return false;
    const r = s.slice(4) + s.slice(0, 4);
    const numeric = r.split("").map((ch) => parseInt(ch, 36).toString()).join("");
    return BigInt(numeric) % 97n === 1n;
  }

  function isValidLuhn(v) {
    const d = digits(v);
    if (d.length < 13 || d.length > 19) return false;
    let total = 0;
    d.reverse().forEach((n, i) => {
      if (i % 2 === 1) n = n * 2 > 9 ? n * 2 - 9 : n * 2;
      total += n;
    });
    return total % 10 === 0;
  }

  const NOT_PASSWORDS = new Set(["password", "passwd", "pwd", "parola", "şifre", "sifre", "secret", "none",
    "null", "true", "false", "undefined", "required", "optional", "string", "example"]);
  const CODE_REF = /^(?:\$|%\(|\{\{|<|os\.|self\.|this\.|process\.env|env\.|config\.|settings\.|getenv|environ)/i;

  function looksLikePassword(value) {
    const v = value.replace(/^["'`]+|["'`]+$/g, "");
    if (NOT_PASSWORDS.has(v.toLowerCase()) || CODE_REF.test(v)) return false;
    if (new Set(v).size === 1) return false;
    if (/^[A-Za-z_]\w*(?:\.\w+)+$/.test(v) || v.includes("(")) return false;
    if (/^[A-Z]\w*\[.*\]$/.test(v)) return false;
    if (/^\[[A-Z_]+_\d+\]$/.test(v)) return false;
    return true;
  }

  // ---------- tanıyıcılar (entity, desen, skor, doğrulayıcı, grup) ----------
  const R = (entity, re, score, validator = null, group = 0) => ({ entity, re, score, validator, group });
  const RECOGNIZERS = [
    R("TCKN", /(?<!\d)[1-9]\d{10}(?!\d)/g, 1.0, isValidTckn),
    R("VKN", /(?:vkn|vergi\s*(?:kimlik\s*)?(?:no|numarası)?)\W{0,3}(\d{10})(?!\d)/gid, 1.0, isValidVkn, 1),
    R("IBAN_TR", /\bTR\d{2}(?:\s?\d{4}){5}\s?\d{2}\b/gi, 1.0, isValidTrIban),
    R("CREDIT_CARD", /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g, 1.0, isValidLuhn),
    R("EMAIL_ADDRESS", /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g, 1.0),
    R("PHONE_TR", /(?<![\d\w])(?:\+?90[\s-]?|0)?\(?5\d{2}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)/g, 0.7),
    R("PLATE_TR", /\b(?:0[1-9]|[1-7]\d|8[01])\s?[A-PR-VYZ]{1,3}\s?\d{2,4}\b/g, 0.6),
    R("SECRET_AWS_KEY", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 1.0),
    R("SECRET_AWS_KEY", /aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gid, 1.0, null, 1),
    R("SECRET_GITHUB_TOKEN", /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g, 1.0),
    R("SECRET_ANTHROPIC_KEY", /\bsk-ant-[A-Za-z0-9_-]{20,}/g, 1.0),
    R("SECRET_OPENAI_KEY", /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, 1.0),
    R("SECRET_SLACK_TOKEN", /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, 1.0),
    R("SECRET_GOOGLE_API_KEY", /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g, 1.0),
    R("SECRET_STRIPE_KEY", /\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b/g, 1.0),
    R("SECRET_PRIVATE_KEY",
      /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----|[\s\S]*)/g, 1.0),
    R("SECRET_JWT", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 1.0),
    R("SECRET_DB_URL",
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/[^\s:/@]+:[^\s@/]+@[^\s"'<>]+/gi, 1.0),
    R("SECRET_PASSWORD", /(?:password|passwd|pwd|parola|şifre|sifre)["']?\s*[=:]\s*["']?([^\s"',;)]{6,})/gid, 0.8,
      looksLikePassword, 1),
  ];
  const MIN_SCORE = 0.5;

  // ---------- kurumsal sözlük (gateway: GET /v1/shadow-ai/dictionary) ----------
  // Terimler eklentiye özet olarak gelir: metindeki kelime grupları gateway'deki gibi normalize
  // edilip (boşluk tekleşir, Türkçe küçük harf) tuzlu SHA-256'nın ilk 64 biti karşılaştırılır.
  // Eşleşme gateway'deki düzenli ifadeyle aynı: tam kelime, soldan, en uzun terim.
  const SHA_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  // Eşzamanlı SHA-256: yapıştırma / gönderim kararı olay içinde verilmeli (crypto.subtle asenkron)
  function sha256Hex(str) {
    const msg = new TextEncoder().encode(str);
    const buf = new Uint8Array(((msg.length + 9 + 63) >> 6) << 6);
    buf.set(msg);
    buf[msg.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(buf.length - 8, Math.floor(msg.length / 0x20000000));
    dv.setUint32(buf.length - 4, (msg.length * 8) >>> 0);
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const w = new Uint32Array(64);
    for (let off = 0; off < buf.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      [a, b, c, d, e, f, g, h].forEach((x, i) => { H[i] = (H[i] + x) | 0; });
    }
    return Array.from(H, (x) => x.toString(16).padStart(8, "0")).join("");
  }

  const HASH_HEX = 16;
  const termHash = (salt, folded) => sha256Hex(`${salt}\n${folded}`).slice(0, HASH_HEX);
  const WORD_RX = /[\p{L}\p{N}]/u;
  const SPACE_RX = /\s/u;
  // gateway: _fold (Türkçe İ/ı eşleri; diğerleri küçük harf)
  const fold = (ch, cs) => cs ? ch : ch === "İ" ? "i" : ch === "I" ? "ı" : ch.toLowerCase();
  const charAt = (s, i) => String.fromCodePoint(s.codePointAt(i));
  const charBefore = (s, i) => i <= 0 ? "" : (i >= 2 && /[\uDC00-\uDFFF]/.test(s[i - 1]) ? s.slice(i - 2, i) : s[i - 1]);
  const isWord = (ch) => ch !== "" && WORD_RX.test(ch);

  let dictionary = null;

  function setDictionary(payload) {
    if (!payload || !payload.salt) { dictionary = null; return { terms: 0, patterns: 0, skipped: 0 }; }
    const terms = (payload.terms || []).map((t) => ({
      entity: t.entity, cs: !!t.case_sensitive, hashes: new Set(t.hashes), lengths: new Set(t.lengths),
      maxLen: Math.max(0, ...t.lengths), maxWords: t.max_words || 1,
    }));
    const patterns = [];
    let skipped = 0;
    for (const p of payload.patterns || []) {
      // gateway: (?<![^\W_]) ... (?![^\W_])  ->  harf / rakam olmayan sınır
      const [left, right] = p.whole_word ? ["(?<![\\p{L}\\p{N}])", "(?![\\p{L}\\p{N}])"] : ["", ""];
      try {
        const re = new RegExp(`${left}(?:${p.pattern})${right}`, "gu" + (p.case_sensitive ? "" : "i"));
        if (re.test("")) throw new Error("boş eşleşme");
        patterns.push(R(p.entity, re, 1.0));
      } catch {
        skipped++;   // Python'a özgü sözdizimi (ör. (?P<ad>)): tarayıcıda aranamaz
      }
    }
    dictionary = { salt: payload.salt, labels: payload.labels || {}, terms, patterns };
    return { terms: terms.reduce((n, t) => n + t.hashes.size, 0), patterns: patterns.length, skipped };
  }

  /** i'de başlayan en uzun terimin bitişi; yoksa -1. */
  function longestTermAt(text, i, t, salt) {
    let norm = "", len = 0, words = 1, best = -1, j = i;
    while (j < text.length) {
      const ch = charAt(text, j);
      if (SPACE_RX.test(ch)) {
        let k = j;
        while (k < text.length && SPACE_RX.test(text[k])) k++;
        if (k >= text.length || ++words > t.maxWords) break;
        norm += " "; len++; j = k;
        continue;
      }
      const f = fold(ch, t.cs);
      norm += f; len += [...f].length; j += ch.length;
      if (len > t.maxLen) break;
      if (t.lengths.has(len) && !isWord(j < text.length ? charAt(text, j) : "") && t.hashes.has(termHash(salt, norm))) best = j;
    }
    return best;
  }

  function dictionaryFindings(text) {
    if (!dictionary) return [];
    const out = [];
    for (const t of dictionary.terms) {
      for (let i = 0; i < text.length;) {
        const ch = charAt(text, i);
        if (!SPACE_RX.test(ch) && !isWord(charBefore(text, i))) {
          const end = longestTermAt(text, i, t, dictionary.salt);
          if (end > 0) { out.push({ entity: t.entity, start: i, end, score: 1.0 }); i = end; continue; }
        }
        i += ch.length;
      }
    }
    return out;
  }

  function analyze(text) {
    const results = dictionaryFindings(text);
    for (const rec of RECOGNIZERS.concat(dictionary ? dictionary.patterns : [])) {
      rec.re.lastIndex = 0;
      let m;
      while ((m = rec.re.exec(text)) !== null) {
        if (m[0] === "") { rec.re.lastIndex++; continue; }
        const value = m[rec.group];
        if (value === undefined) continue;
        if (rec.validator && !rec.validator(value)) continue;
        const start = rec.group ? m.indices[rec.group][0] : m.index;
        results.push({ entity: rec.entity, start, end: start + value.length, score: rec.score });
      }
    }
    // Çakışmada yüksek skor, eşitse uzun olan kazanır (Python ile aynı; kararlı sıralama)
    const ranked = results.filter((r) => r.score >= MIN_SCORE)
      .map((r, i) => ({ ...r, i }))
      .sort((a, b) => (b.score - a.score) || ((b.end - b.start) - (a.end - a.start)) || (a.i - b.i));
    const kept = [];
    for (const r of ranked) {
      if (kept.every((k) => r.end <= k.start || r.start >= k.end)) kept.push(r);
    }
    return kept.sort((a, b) => a.start - b.start).map(({ i, ...r }) => r);
  }

  /** Geri çevrilemez yerel maskeleme: yapıştırılan metin [TCKN_1] gibi yer tutucularla gider.
   *  continueNumbering: metinde zaten [TCKN_1] varsa (önceden maskeli yapıştırılmış) yeni değer
   *  [TCKN_2] olur; aynı yer tutucu iki farklı değeri göstermesin. */
  function mask(text, { continueNumbering = false } = {}) {
    const findings = analyze(text);
    const counters = {};
    if (continueNumbering) {
      for (const m of text.matchAll(/\[([A-Z][A-Z0-9_]*)_(\d+)\]/g)) {
        counters[m[1]] = Math.max(counters[m[1]] || 0, Number(m[2]));
      }
    }
    const seen = new Map();
    let out = "";
    let cursor = 0;
    for (const f of findings) {
      const original = text.slice(f.start, f.end);
      let ph = seen.get(original);
      if (!ph) {
        counters[f.entity] = (counters[f.entity] || 0) + 1;
        ph = `[${f.entity}_${counters[f.entity]}]`;
        seen.set(original, ph);
      }
      out += text.slice(cursor, f.start) + ph;
      cursor = f.end;
    }
    return { text: out + text.slice(cursor), findings };
  }

  const LABELS = {
    TCKN: "T.C. kimlik no", VKN: "Vergi kimlik no", IBAN_TR: "IBAN", CREDIT_CARD: "Kredi kartı",
    EMAIL_ADDRESS: "E-posta", PHONE_TR: "Telefon", PLATE_TR: "Araç plakası",
  };
  const label = (e) => LABELS[e] || (dictionary && dictionary.labels[e]) ||
    (e.startsWith("SECRET_") ? "Sır: " + e.slice(7).toLowerCase().replace(/_/g, " ")
      : e.startsWith("KURUM_") ? "Kurum terimi: " + e.slice(6).toLowerCase().replace(/_/g, " ") : e);

  const api = { analyze, mask, label, setDictionary, termHash, sha256Hex,
    isValidTckn, isValidVkn, isValidTrIban, isValidLuhn, looksLikePassword };
  root.TelveguardDetectors = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : globalThis);
