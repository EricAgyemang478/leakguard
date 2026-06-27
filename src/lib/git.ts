import { execFileSync } from "node:child_process";

/**
 * Thin wrappers over the `git` CLI used by the --staged (pre-commit) and --diff
 * (pre-push / CI) scan modes. We scan the *staged blob* rather than the working
 * file, so a commit is judged on exactly what it will publish.
 */
function git(args: string[]): string {
  return execFileSync("git", args, {
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
  });
}

/** Files staged for commit (added / copied / modified). */
export function stagedFiles(): string[] {
  return toLines(git(["diff", "--cached", "--name-only", "--diff-filter=ACM"]));
}

/** The exact staged content of a file (what will be committed). */
export function stagedContent(file: string): string {
  try {
    return git(["show", `:${file}`]);
  } catch {
    return "";
  }
}

/** Files added/modified within a commit range, e.g. "origin/main..HEAD". */
export function diffFiles(range: string): string[] {
  return toLines(git(["diff", "--name-only", "--diff-filter=ACM", range]));
}

function toLines(out: string): string[] {
  return out
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}
