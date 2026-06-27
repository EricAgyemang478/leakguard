export type Severity = "critical" | "high" | "medium" | "low";

/** A compiled detection rule for a known secret/credential format. */
export interface Rule {
  id: string;
  description: string;
  regex: RegExp;
  severity: Severity;
}

/** A filename-based rule — flags committing a sensitive file by name. */
export interface FilenameRule {
  id: string;
  description: string;
  regex: RegExp;
  severity: Severity;
}

/** A single potential secret found in the scanned content. */
export interface Finding {
  file: string;
  line: number; // 1-based
  column: number; // 1-based
  ruleId: string;
  severity: Severity;
  description: string;
  match: string; // the raw matched secret (redacted before display unless --no-redact)
  fingerprint: string; // stable hash of file+rule+secret, for the baseline
}

export interface ScanOptions {
  entropy: boolean;
  minEntropyLength: number;
  base64Threshold: number;
  hexThreshold: number;
  baseline: Set<string>; // fingerprints to suppress
}

export const DEFAULT_SCAN_OPTIONS: Omit<ScanOptions, "baseline"> = {
  entropy: true,
  minEntropyLength: 20,
  base64Threshold: 4.5,
  hexThreshold: 3.0,
};
