# Changelog

All notable changes to `pi-noleaks-personal` are documented here.

## [1.0.0] - 2026-07-02

### Added
- Initial personal fork of [`@raquezha/noleaks`](https://pi.dev/packages/@raquezha/noleaks).
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
  - Mode persistence via `~/.pi/agent/noleaks.json`.
- Richer redaction set: Vault (`hvs.`), Doppler (`dp.pt.`), 1Password (`op://`),
  Bearer tokens, DB URLs with credentials, plus the original's AWS/OpenAI/Anthropic/
  Google/GitHub/GitLab/Slack/Stripe/SendGrid/npm/JWT/private-key patterns.
- Interactive read confirmation (max mode) and detailed per-category/per-pattern
  session stats.
- Pure, unit-tested security helpers in `security.ts` (34 tests).
