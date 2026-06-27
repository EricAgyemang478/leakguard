/**
 * Entropy-based detection — the catch-all for secrets that don't match a known
 * provider format. We isolate candidate tokens on a line and flag the ones whose
 * Shannon entropy is high enough to look random, with several guards to keep the
 * false-positive rate low (hashes, low character-class diversity, etc.).
 */

/** Shannon entropy in bits per character. */
export function shannonEntropy(input: string): number {
  if (!input) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export interface EntropyHit {
  token: string;
  index: number; // 0-based offset within the line
  entropy: number;
}

export interface EntropyConfig {
  minLength: number;
  base64Threshold: number;
  hexThreshold: number;
}

// base64 / base64url-ish run, and a pure-hex run.
const BASE64ish = /[A-Za-z0-9+/=_-]{16,}/g;
const HEXish = /\b[0-9a-fA-F]{16,}\b/g;

export function entropyHits(line: string, cfg: EntropyConfig): EntropyHit[] {
  const hits: EntropyHit[] = [];
  const seen = new Set<string>();

  const add = (token: string, index: number, threshold: number) => {
    if (token.length < cfg.minLength) return;
    if (isLikelyHash(token)) return;
    const key = `${index}:${token}`;
    if (seen.has(key)) return;
    const entropy = shannonEntropy(token);
    if (entropy >= threshold) {
      seen.add(key);
      hits.push({ token, index, entropy });
    }
  };

  // Pure-hex tokens are scored with the lower hex threshold.
  for (const m of line.matchAll(HEXish)) {
    add(m[0], m.index ?? 0, cfg.hexThreshold);
  }

  // base64-ish tokens (skip the pure-hex ones already handled, and require
  // mixed character classes so plain words/identifiers don't trip).
  for (const m of line.matchAll(BASE64ish)) {
    const token = m[0];
    if (/^[0-9a-fA-F]+$/.test(token)) continue;
    if (!hasMixedClasses(token)) continue;
    if (looksLikeEncodedText(token)) continue;
    add(token, m.index ?? 0, cfg.base64Threshold);
  }

  return hits;
}

/**
 * True when a standard-base64 token decodes to mostly-printable text — i.e. it's
 * encoded *data* (a sentence, JSON, etc.), not a random credential. Real secret
 * keys decode to high-entropy binary, so this only suppresses the false positive.
 */
function looksLikeEncodedText(token: string): boolean {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(token) || token.length % 4 !== 0) return false;
  let decoded: string;
  try {
    decoded = Buffer.from(token, "base64").toString("latin1");
  } catch {
    return false;
  }
  if (decoded.length < 4) return false;
  let printable = 0;
  for (let i = 0; i < decoded.length; i++) {
    const c = decoded.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
  }
  return printable / decoded.length > 0.85;
}

/** md5 (32), sha1 / git sha (40), and sha256 (64) hex strings are almost always hashes. */
function isLikelyHash(token: string): boolean {
  return /^[0-9a-fA-F]+$/.test(token) && [32, 40, 64].includes(token.length);
}

function hasMixedClasses(token: string): boolean {
  let classes = 0;
  if (/[a-z]/.test(token)) classes++;
  if (/[A-Z]/.test(token)) classes++;
  if (/[0-9]/.test(token)) classes++;
  if (/[^A-Za-z0-9]/.test(token)) classes++;
  return classes >= 3;
}
