import path from "node:path";
import { RULES, FILENAME_RULES } from "./rules.js";
import { entropyHits } from "./lib/entropy.js";
import { isLineAllowlisted, fingerprint } from "./lib/allowlist.js";
import type { Finding, ScanOptions } from "./types.js";

const ENTROPY_RULE_ID = "high-entropy-string";
const MAX_LINE_LENGTH = 5000; // skip pathological minified lines

// Lines whose high-entropy strings are almost always non-secrets: integrity
// hashes, public keys, certificates, data URIs. Rules still run on these lines;
// only the entropy heuristic is suppressed.
const ENTROPY_NOISE =
  /integrity|sha(?:1|256|384|512)-|ssh-(?:rsa|ed25519|dss)|BEGIN (?:PUBLIC|CERTIFICATE)|data:[^;]*;base64,/i;

/** Scan a single file's content and return findings. Pure — no I/O. */
export function scanContent(file: string, content: string, opts: ScanOptions): Finding[] {
  const findings: Finding[] = [];
  const display = file.replace(/\\/g, "/");
  const lines = content.split(/\r?\n/);
  let inPemBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (line.length > MAX_LINE_LENGTH) continue;
    if (isLineAllowlisted(line)) continue;
    if (/-----BEGIN [^-]+-----/.test(line)) inPemBlock = true;

    for (const rule of RULES) {
      const re = ensureGlobal(rule.regex);
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        push(
          findings,
          display,
          i + 1,
          (m.index ?? 0) + 1,
          rule.id,
          rule.severity,
          rule.description,
          m[0],
          opts,
        );
        if (m[0] === "") re.lastIndex++;
      }
    }

    if (opts.entropy && !inPemBlock && !ENTROPY_NOISE.test(line)) {
      const hits = entropyHits(line, {
        minLength: opts.minEntropyLength,
        base64Threshold: opts.base64Threshold,
        hexThreshold: opts.hexThreshold,
      });
      for (const hit of hits) {
        // Don't double-report something a precise rule already caught on this line.
        if (findings.some((f) => f.line === i + 1 && f.match === hit.token)) continue;
        push(
          findings,
          display,
          i + 1,
          hit.index + 1,
          ENTROPY_RULE_ID,
          "medium",
          `High-entropy string (${hit.entropy.toFixed(1)} bits/char)`,
          hit.token,
          opts,
        );
      }
    }

    if (/-----END [^-]+-----/.test(line)) inPemBlock = false;
  }

  return dedupeBySpan(findings);
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 } as const;

/** Collapse multiple rules matching the exact same span, keeping the most severe. */
function dedupeBySpan(findings: Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.line}:${f.column}:${f.match}`;
    const current = best.get(key);
    if (!current || SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[current.severity]) {
      best.set(key, f);
    }
  }
  return [...best.values()];
}

/** Flag a sensitive file purely by its name/path (e.g. committing a .env or a key). */
export function scanFilename(file: string): Finding[] {
  const base = path.basename(file);
  const display = file.replace(/\\/g, "/");
  const findings: Finding[] = [];
  for (const rule of FILENAME_RULES) {
    if (rule.regex.test(base)) {
      const fp = fingerprint(display, rule.id, base);
      findings.push({
        file: display,
        line: 0,
        column: 0,
        ruleId: rule.id,
        severity: rule.severity,
        description: rule.description,
        match: base,
        fingerprint: fp,
      });
    }
  }
  return findings;
}

function push(
  findings: Finding[],
  file: string,
  line: number,
  column: number,
  ruleId: string,
  severity: Finding["severity"],
  description: string,
  match: string,
  opts: ScanOptions,
): void {
  const fp = fingerprint(file, ruleId, match);
  if (opts.baseline.has(fp)) return;
  findings.push({ file, line, column, ruleId, severity, description, match, fingerprint: fp });
}

/** Return a global-flagged clone so exec() can iterate all matches on a line. */
function ensureGlobal(re: RegExp): RegExp {
  return re.global ? re : new RegExp(re.source, re.flags + "g");
}
