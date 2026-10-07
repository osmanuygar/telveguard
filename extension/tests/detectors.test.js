/*
 * JS motoru == Python motoru mu? (fixtures.json ve dictionary_fixtures.json'u Python üretir:
 * tests/test_extension_parity.py)
 *   node extension/tests/detectors.test.js
 * Tarayıcıda: detectors.test.html
 */
(function (root) {
  "use strict";

  // Metinler base64 (UTF-8): sahte anahtarlar dosyada düz durmasın (GitHub secret scanning)
  const decode = (b64) => new TextDecoder().decode(Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0)));

  // dictFixtures: { payload: gateway'in /v1/shadow-ai/dictionary cevabı, cases: [...] }
  function run(D, fixturesRaw, dictFixtures) {
    const failures = [];
    let total = check(D, fixturesRaw, "", failures);
    if (dictFixtures) {
      D.setDictionary(dictFixtures.payload);
      try { total += check(D, dictFixtures.cases, "sözlük ", failures); } finally { D.setDictionary(null); }
    }
    return { total, failures };
  }

  function check(D, fixturesRaw, prefix, failures) {
    const fixtures = fixturesRaw.map((c) => ({ text: decode(c.text_b64), findings: c.findings, masked: decode(c.masked_b64) }));
    fixtures.forEach((c, n) => {
      const i = prefix + n;
      const got = D.analyze(c.text).map((f) => [f.entity, f.start, f.end]);
      if (JSON.stringify(got) !== JSON.stringify(c.findings)) {
        failures.push({ case: i, text: c.text, expected: c.findings, got });
      }
      const masked = D.mask(c.text).text;
      if (masked !== c.masked) failures.push({ case: i, text: c.text, expected_masked: c.masked, got_masked: masked });
    });
    return fixtures.length;
  }

  root.TelveguardDetectorTests = { run };

  if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
    const path = require("path");
    const fs = require("fs");
    const D = require(path.join(__dirname, "..", "src", "detectors.js"));
    const read = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, name), "utf8"));
    const { total, failures } = run(D, read("fixtures.json"), read("dictionary_fixtures.json"));
    if (failures.length) {
      console.error(JSON.stringify(failures, null, 1));
      console.error(`BAŞARISIZ: ${failures.length} / ${total}`);
      process.exit(1);
    }
    console.log(`JS motoru Python ile tutarlı: ${total} örnek`);
  }
})(typeof self !== "undefined" ? self : globalThis);
