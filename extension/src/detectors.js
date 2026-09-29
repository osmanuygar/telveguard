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

  function analyze(text) {
    const results = [];
    for (const rec of RECOGNIZERS) {
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

  /** Geri çevrilemez yerel maskeleme: yapıştırılan metin [TCKN_1] gibi yer tutucularla gider. */
  function mask(text) {
    const findings = analyze(text);
    const counters = {};
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
  const label = (e) => LABELS[e] || (e.startsWith("SECRET_") ? "Sır: " + e.slice(7).toLowerCase().replace(/_/g, " ") : e);

  const api = { analyze, mask, label, isValidTckn, isValidVkn, isValidTrIban, isValidLuhn, looksLikePassword };
  root.TelveguardDetectors = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : globalThis);
