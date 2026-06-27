# leakguard

[![CI](https://img.shields.io/github/actions/workflow/status/your-handle/leakguard/ci.yml?branch=main&label=CI)](https://github.com/your-handle/leakguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-34d399)](./LICENSE)
[![deps](https://img.shields.io/badge/runtime%20deps-0-blue)](package.json)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-339933)](.nvmrc)

**Catch credentials before they go public.** A fast, **zero-dependency** secret
scanner that runs three ways — a **CLI**, a **git pre-commit / pre-push hook**,
and a **GitHub Action** — so a secret is stopped at the earliest possible point,
not discovered after it's been pushed (where the only safe fix is rotation).

```
✗ leakguard: 1 potential secret(s) found.
  CRITICAL  src/config.ts:14:22  [aws-access-key-id]
            AWS Access Key ID
            AKI…LE (20 chars)  ·  fingerprint 0e941deced0257a7
```

## Why

A leaked key in git history is **irreversible** — deleting the file doesn't help;
public commits are scraped within minutes, so the credential must be rotated.
leakguard's job is to make sure it never reaches that point.

## What it detects

- **90 rules across 45+ providers** — AWS, GitHub/GitLab, Google/GCP, Slack,
  Stripe, OpenAI/Anthropic/OpenRouter/HuggingFace, Twilio, SendGrid, Mailgun,
  Resend, npm, PyPI, Datadog, Sentry, Doppler, Cloudflare, DigitalOcean, Plaid,
  Shopify, Discord, Telegram, Supabase, Square, Atlassian, Notion, Postman, and more.
- **Entropy detection** for unknown/custom secrets — high-Shannon-entropy tokens,
  with guards that suppress the usual noise (git/SHA hashes, integrity hashes,
  PEM blocks, public keys, and base64-of-text).
- **Filename rules** — flags committing a `.env`, `id_rsa`, `*.pem`, keystore, etc.
- **Private keys** — RSA / EC / OpenSSH / PGP / PKCS#8 / PuTTY blocks.

Every rule is verified against its own samples and an **adversarial corpus** of
real-looking secrets (must flag) and tricky decoys (must not) — see
[Validation](#validation).

## Install & use

```bash
npm install        # dev deps only — leakguard has zero runtime deps
npm run build

node dist/cli.js scan .          # scan a directory
node dist/cli.js install-hooks   # install git pre-commit + pre-push hooks
```

| Command                         | What it does                                     |
| ------------------------------- | ------------------------------------------------ |
| `leakguard scan [path]`         | Scan a directory (default `.`)                   |
| `leakguard scan --staged`       | Scan git-staged content — use in **pre-commit**  |
| `leakguard scan --diff <range>` | Scan files changed in a commit range             |
| `leakguard install-hooks`       | Install pre-commit + pre-push hooks in this repo |

Flags: `--json`, `--no-entropy`, `--no-redact`, `--no-filename`, `--baseline <file>`.
**Exit code is `1` when any secret is found**, so it blocks commits, pushes, and CI.

### In CI

Copy [`examples/github-action.yml`](examples/github-action.yml) to
`.github/workflows/leakguard.yml`. It fails the build on any finding.

## Suppressing false positives

Three mechanisms, most-local first:

1. **Inline** — add `leakguard:allow` (or `pragma: allowlist secret`) to the line.
2. **Path** — add a gitignore-style glob to `.leakguardignore`.
3. **Baseline** — record accepted finding fingerprints in `.leakguard-baseline.json`
   (each finding prints its fingerprint) so reviewed items don't re-alert while new
   ones still do.

## Validation

leakguard is tested the way a security tool should be:

- **Per-rule regression** — every rule must match its own example samples.
- **Adversarial corpus** — 43 real-looking secrets across providers that **must**
  be flagged, and 39 decoys (UUIDs, git SHAs, integrity hashes, base64 text,
  public keys, placeholders) that **must not** be — zero false positives.
- **Stress-tested** — 400 files (~3.3 MB) scan in ~1.2 s; binary files, minified
  lines, deep trees, and unicode are all handled.

Full design rationale in **[ARCHITECTURE.md](./ARCHITECTURE.md)**.

## Project structure

```
src/
├── cli.ts        # arg parsing, scan modes, hook installer, exit codes
├── scanner.ts    # per-line orchestration: rules + entropy + dedupe
├── rules.ts      # 90 content rules + filename rules
├── reporter.ts   # findings output (pretty / JSON) + redaction
└── lib/
    ├── entropy.ts    # Shannon entropy + false-positive guards
    ├── allowlist.ts  # inline / .leakguardignore / baseline
    ├── git.ts        # staged + diff content
    └── walk.ts       # file discovery (skips deps, binaries, lockfiles)
test/                 # per-rule, corpus, and unit tests
```

## License

[MIT](./LICENSE) © Eric Agyemang
