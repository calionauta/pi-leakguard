# Changelog

All notable changes to `pi-leakguard` are documented here.

## [0.2.0] - 2026-07-08

### Added
- `/leakguard trust <pattern>` — session-level allow-list for redaction bypass.
  Literal string or `/regex/` syntax. Human-only via pi command.
- `trust list`, `trust clear`, `trust remove <n>` sub-commands.
- Informative placeholder: `[LEAKGUARD_REDACTED — JWT Token]` shows the pattern
  name that matched, giving the LLM context to ask for the right trust pattern.

### Security
- LLM never self-bypasses. Trust is human-only, same model as `allow-once`/`yolo`/`mode`.

### Tests
- 8 new tests: parseTrustedPattern (literal, regex, case-insensitive), trustedTest
  skip/isolation, informative placeholder (AWS key, JWT Token, safe text).

## [0.1.0] - 2026-07-02

### Added
- Initial project, inspired by [`@raquezha/noleaks`](https://pi.dev/packages/@raquezha/noleaks) (MIT, published on npm/pi.dev; independent continuation, MIT attribution retained).
- All security layers from the original, ported and tested:
  - Symlink guard (`realpathSync` before path checks).
  - Obfuscation detection (NFKC normalization variance + hidden/control chars).
  - Env-dump block (`env`/`printenv`/`set`/`export`).
  - Sensitive shell expansion (`$TOKEN`, `$SECRET`, ...).
  - Transform+smuggle (`base64`/`openssl`/`gpg` piping secret material).
  - Discovery/exfil combine (`nmap`/`curl`/`nc` + sensitive material).
  - Universal word scan (critical utilities as nested arguments: `sudo chmod`, `dd`, `shred`).
  - Write/edit payload scan (`hasSecretMaterial`).
  - `grep`/`find`/`ls` guards over sensitive paths (max mode).
  - Mode persistence via `~/.pi/agent/leakguard.json`.
- Richer redaction set: Vault (`hvs.`), Doppler (`dp.pt.`), 1Password (`op://`),
  Bearer tokens, DB URLs with credentials, plus the original's AWS/OpenAI/Anthropic/
  Google/GitHub/GitLab/Slack/Stripe/SendGrid/npm/JWT/private-key patterns.
- Interactive read confirmation (max mode) and detailed per-category/per-pattern
  session stats.
- Pure, unit-tested security helpers in `security.ts` (34 tests).
