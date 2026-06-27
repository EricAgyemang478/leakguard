import type { Finding, Severity } from "./types.js";

/** Mask a secret so the report itself never leaks it. */
export function redact(secret: string): string {
  if (secret.length <= 8) return "*".repeat(secret.length);
  return `${secret.slice(0, 3)}…${secret.slice(-2)} (${secret.length} chars)`;
}

const ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export interface ReportOptions {
  json: boolean;
  redactSecrets: boolean;
}

export function report(findings: Finding[], opts: ReportOptions): string {
  const sorted = [...findings].sort(
    (a, b) =>
      ORDER[a.severity] - ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line,
  );

  if (opts.json) {
    return JSON.stringify(
      sorted.map((f) => ({ ...f, match: opts.redactSecrets ? redact(f.match) : f.match })),
      null,
      2,
    );
  }

  if (sorted.length === 0) {
    return "✓ leakguard: no secrets found";
  }

  const lines: string[] = [];
  for (const f of sorted) {
    const shown = opts.redactSecrets ? redact(f.match) : f.match;
    lines.push(
      `  ${f.severity.toUpperCase().padEnd(8)} ${f.file}:${f.line}:${f.column}  [${f.ruleId}]`,
    );
    lines.push(`           ${f.description}`);
    lines.push(`           ${shown}  ·  fingerprint ${f.fingerprint}`);
    lines.push("");
  }
  lines.push(`✗ leakguard: ${sorted.length} potential secret(s) found.`);
  lines.push("  Suppress a confirmed false positive with an inline 'leakguard:allow' comment,");
  lines.push("  a path in .leakguardignore, or its fingerprint in .leakguard-baseline.json.");
  return lines.join("\n");
}
