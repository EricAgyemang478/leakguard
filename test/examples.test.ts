import { test } from "node:test";
import assert from "node:assert/strict";
import { RULES } from "../src/rules.js";
import { RULE_EXAMPLES } from "./examples.js";

const byId = new Map(RULES.map((r) => [r.id, r.regex]));

test("every rule matches each of its own example samples", () => {
  const failures: string[] = [];
  for (const { id, examples } of RULE_EXAMPLES) {
    const re = byId.get(id);
    if (!re) {
      failures.push(`rule not found: ${id}`);
      continue;
    }
    for (const ex of examples) {
      const g = re.global ? re : new RegExp(re.source, re.flags + "g");
      g.lastIndex = 0;
      if (!g.test(ex)) failures.push(`${id} did not match: ${ex}`);
    }
  }
  assert.deepEqual(failures, [], `\n${failures.join("\n")}`);
});

test("rule ids are unique", () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});
