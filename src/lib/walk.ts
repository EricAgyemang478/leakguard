import fs from "node:fs";
import path from "node:path";

/**
 * Recursively list scannable files under a root. Skips VCS/dependency/build
 * directories, binary and lockfile types, and anything over the size cap — the
 * places real source secrets live are small text files.
 */
const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  ".next",
  ".astro",
  ".turbo",
  "coverage",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
]);

const SKIP_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".ico",
  ".svg",
  ".pdf",
  ".zip",
  ".gz",
  ".tgz",
  ".tar",
  ".7z",
  ".rar",
  ".mp4",
  ".mov",
  ".webm",
  ".mp3",
  ".wav",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".otf",
  ".class",
  ".jar",
  ".wasm",
  ".node",
  ".dll",
  ".so",
  ".dylib",
  ".exe",
  ".bin",
]);

const SKIP_FILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "npm-shrinkwrap.json",
  "composer.lock",
  "Gemfile.lock",
  "poetry.lock",
  "Cargo.lock",
]);

const MAX_BYTES = 2 * 1024 * 1024;

export function walk(root: string): string[] {
  const out: string[] = [];
  const stack: string[] = [root];

  while (stack.length) {
    const dir = stack.pop();
    if (dir === undefined) break;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        if (isScannable(entry.name, full)) out.push(full);
      }
    }
  }
  return out;
}

function isScannable(name: string, full: string): boolean {
  if (SKIP_FILES.has(name)) return false;
  const ext = path.extname(name).toLowerCase();
  if (SKIP_EXTS.has(ext)) return false;
  if (name.endsWith(".min.js") || name.endsWith(".map")) return false;
  try {
    if (fs.statSync(full).size > MAX_BYTES) return false;
  } catch {
    return false;
  }
  return true;
}
