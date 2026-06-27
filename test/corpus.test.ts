import { test } from "node:test";
import assert from "node:assert/strict";
import { scanContent } from "../src/scanner.js";
import { POSITIVES, NEGATIVES } from "./corpus.js";
import { DEFAULT_SCAN_OPTIONS } from "../src/types.js";

const opts = { ...DEFAULT_SCAN_OPTIONS, baseline: new Set<string>() };

test("every real secret in the corpus is flagged", () => {
  const missed: string[] = [];
  for (const p of POSITIVES) {
    if (scanContent("sample.txt", p.sample, opts).length === 0) {
      missed.push(`${p.provider}: ${p.sample}`);
    }
  }
  assert.deepEqual(missed, [], `missed ${missed.length} positive(s):\n${missed.join("\n")}`);
});

test("no decoy in the corpus is flagged (false-positive guard)", () => {
  const falsePositives: string[] = [];
  for (const n of NEGATIVES) {
    const findings = scanContent("sample.txt", n.sample, opts);
    if (findings.length > 0) {
      falsePositives.push(`${n.sample}  ->  ${findings.map((f) => f.ruleId).join(", ")}`);
    }
  }
  assert.deepEqual(
    falsePositives,
    [],
    `${falsePositives.length} false positive(s):\n${falsePositives.join("\n")}`,
  );
});
