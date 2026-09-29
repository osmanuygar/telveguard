/*
 * JS motoru == Python motoru mu? (fixtures.json'u Python üretir: tests/test_extension_parity.py)
 *   node extension/tests/detectors.test.js
 * Tarayıcıda: detectors.test.html
 */
(function (root) {
  "use strict";

  // Metinler base64 (UTF-8): sahte anahtarlar dosyada düz durmasın (GitHub secret scanning)
  const decode = (b64) => new TextDecoder().decode(Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0)));

  function run(D, fixturesRaw) {
    const fixtures = fixturesRaw.map((c) => ({ text: decode(c.text_b64), findings: c.findings, masked: decode(c.masked_b64) }));
    const failures = [];
    fixtures.forEach((c, i) => {
      const got = D.analyze(c.text).map((f) => [f.entity, f.start, f.end]);
      if (JSON.stringify(got) !== JSON.stringify(c.findings)) {
        failures.push({ case: i, text: c.text, expected: c.findings, got });
      }
      const masked = D.mask(c.text).text;
      if (masked !== c.masked) failures.push({ case: i, text: c.text, expected_masked: c.masked, got_masked: masked });
    });
    return { total: fixtures.length, failures };
  }

  root.TelveguardDetectorTests = { run };

  if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
    const path = require("path");
    const fs = require("fs");
    const D = require(path.join(__dirname, "..", "src", "detectors.js"));
    const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures.json"), "utf8"));
    const { total, failures } = run(D, fixtures);
    if (failures.length) {
      console.error(JSON.stringify(failures, null, 1));
      console.error(`BAŞARISIZ: ${failures.length} / ${total}`);
      process.exit(1);
    }
    console.log(`JS motoru Python ile tutarlı: ${total} örnek`);
  }
})(typeof self !== "undefined" ? self : globalThis);
