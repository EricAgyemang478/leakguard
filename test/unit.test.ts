import { test } from "node:test";
import assert from "node:assert/strict";
import { shannonEntropy, entropyHits } from "../src/lib/entropy.js";
import { isLineAllowlisted, globToRegExp, pathIgnored } from "../src/lib/allowlist.js";
import { redact } from "../src/reporter.js";
import { scanContent, scanFilename } from "../src/scanner.js";
import { DEFAULT_SCAN_OPTIONS } from "../src/types.js";

const opts = { ...DEFAULT_SCAN_OPTIONS, baseline: new Set<string>() };
const entropyCfg = { minLength: 20, base64Threshold: 4.5, hexThreshold: 3.0 };

// Built by concatenation so the literal secret never appears in source — which
// would otherwise trip secret-scanning push protection on this very repo.
const AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
const GH_TOKEN = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz";

test("shannonEntropy: low for repeats, high for random", () => {
  assert.ok(shannonEntropy("aaaaaaaaaaaa") < 1);
  assert.ok(shannonEntropy("aB3$xK9z!Qw7vR2") > 3);
});

test("entropy ignores git/sha-style hashes", () => {
  const sha = "0123456789abcdef0123456789abcdef01234567"; // 40 hex
  assert.equal(entropyHits(`commit ${sha}`, entropyCfg).length, 0);
});

test("inline allowlist comment is detected", () => {
  assert.equal(isLineAllowlisted('k = "x" // leakguard:allow'), true);
  assert.equal(isLineAllowlisted('k = "x" // pragma: allowlist secret'), true);
  assert.equal(isLineAllowlisted("k = 1"), false);
});

test("glob ignore matches gitignore-style paths", () => {
  assert.equal(pathIgnored("test/fixtures/keys.txt", [globToRegExp("test/fixtures/**")]), true);
  assert.equal(pathIgnored("src/index.ts", [globToRegExp("test/fixtures/**")]), false);
});

test("redact never reveals the raw secret", () => {
  const r = redact(GH_TOKEN);
  assert.ok(!r.includes("0123456789"));
});

test("inline allowlist suppresses a real finding", () => {
  const line = `token = "${GH_TOKEN}" // leakguard:allow`;
  assert.equal(scanContent("f.ts", line, opts).length, 0);
});

test("baseline suppresses a finding by fingerprint", () => {
  const first = scanContent("f.ts", AWS_KEY, opts);
  assert.ok(first.length >= 1);
  const baseline = new Set(first.map((f) => f.fingerprint));
  assert.equal(scanContent("f.ts", AWS_KEY, { ...opts, baseline }).length, 0);
});

test("filename rules flag sensitive files but not safe ones", () => {
  assert.ok(scanFilename(".env").length >= 1);
  assert.ok(scanFilename("server.pem").length >= 1);
  assert.ok(scanFilename("id_rsa").length >= 1);
  assert.equal(scanFilename(".env.example").length, 0);
  assert.equal(scanFilename("README.md").length, 0);
});

test("empty and pathological lines are handled safely", () => {
  assert.equal(scanContent("f.ts", "", opts).length, 0);
  assert.equal(scanContent("f.ts", "a".repeat(20000), opts).length, 0);
});

test("a clean config line produces no findings", () => {
  const line = "export const PORT = 3000; // default port";
  assert.equal(scanContent("f.ts", line, opts).length, 0);
});
