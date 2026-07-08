# pi-leakguard

Personal **noleaks** extension for [pi.dev](https://pi.dev) — a defense-in-depth
"seatbelt" that blocks the LLM from reading/writing/exfiltrating credentials and
redacts secrets from tool output before the model ever sees them.

> **Inspired by `@raquezha/noleaks`** (MIT, by raquezha). This personal fork
> keeps the original's security layers and adds a richer redaction set, interactive
> confirmation on every block, detailed session stats, and mode persistence.
> Credit for the core bash-security logic (symlink guard, obfuscation detection,
> env-dump/sensitive-expansion blocks, transform-smuggle, discovery/exfil combine,
> universal word scan, write-payload scan, grep/find/ls guards, and `noleaks.json`
> persistence) goes to that project.
>
> **Note:** the original `@raquezha/noleaks` repository appears to have been
> removed from GitHub/npm. This project is an independent continuation that
> preserves and extends its ideas. The MIT license and attribution are retained.

> **Security model:** `leakguard` is a powerful defense-in-depth
> "seatbelt", **not** an airtight sandbox. It prevents accidental leaks and stops
> common AI exfiltration techniques. For untrusted code or unattended automation,
> always use a real sandbox (Docker, Micro-VM).

## Features

- **Path protection**: blocks reads/writes/deletes of sensitive paths
  (`.env`, `~/.ssh/`, `~/.aws/`, `/etc/shadow`, Keychains, etc.)
- **Secret redaction**: scrubs API keys, tokens, passwords, private-key blocks,
  DB URLs, and secret assignments from `tool_result` content.
- **Symlink guard**: paths are resolved to their *real* on-disk location before
  checks, so symlink bypasses are caught.
- **Obfuscation detection**: NFKC normalization variance and hidden/control
  characters (homoglyph / zero-width attacks) are rejected.
- **Shell exfiltration blocks**: env dumps (`env`/`printenv`/`set`/`export`),
  sensitive variable expansion (`$TOKEN`), transform+smuggle (`base64`/`openssl`
  piping secrets), and discovery/exfil combine (`nmap`/`curl` + secrets).
- **Universal word scan**: critical utilities blocked even as nested arguments
  (`sudo chmod`, `dd`, `shred`, `mkfs`, ...).
- **Write/edit payload scan**: writes whose body contains secret-looking
  material are blocked.
- **grep / find / ls guards**: those tools are blocked over sensitive paths in
  `max` mode.
- **Three modes** (persisted to `~/.pi/agent/noleaks.json`):
  - `max` (default) — block sensitive paths AND redact secrets
  - `basic` — allow reads but still redact secrets (Safe Debugging)
  - `off` — disable all protection (dangerous)

## What it blocks (in MAX mode)

| Category        | Examples                                                      |
| --------------- | ------------------------------------------------------------- |
| Environment     | `.env`, `.env.local`, `.env.production`                       |
| Private keys    | `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.p12`, `*.keystore` |
| Credentials     | `auth.json`, `.npmrc`, `.netrc`, `.pypirc`, `.git-credentials` |
| Cloud config    | `~/.aws/`, `~/.azure/`, `~/.config/gcloud/`, `~/.docker/`, `~/.kube/` |
| SSH / GPG       | `~/.ssh/`, `~/.gnupg/`                                        |
| Pi secrets      | `.pi-secrets/`                                                |
| Shell config    | `.bashrc`, `.zshrc`, `.profile`                               |
| System          | `/etc/shadow`, `/etc/sudoers`, `/etc/passwd`                  |
| macOS Keychain  | `~/Library/Keychains/`                                        |

## What it redacts

AWS, OpenAI, Anthropic, Google, GitHub (PAT + fine-grained), GitLab, Slack,
Stripe, SendGrid, npm, HashiCorp **Vault**, **Doppler**, **1Password** (`op://`),
JWTs, private-key blocks, DB URLs with credentials, generic
`key=`/`password=`/`token=` assignments, and `Bearer` tokens.

## Commands

| Command              | Description                                   |
| -------------------- | --------------------------------------------- |
| `/noleaks`           | Show session statistics (blocked, redacted)   |
| `/noleaks mode max`  | Block sensitive paths AND redact secrets      |
| `/noleaks mode basic`| Allow reads but still redact secrets          |
| `/noleaks mode off`  | Disable all protection (dangerous)            |

## Installation (local)

Already installed at `~/.pi/agent/extensions/leakguard/`. Auto-loaded by pi.

## Installation (from GitHub)

```bash
pi install git:github.com/calionauta/pi-leakguard
```

Or pin a version:

```bash
pi install git:github.com/calionauta/pi-leakguard@v1.0.0
```

## Development

```bash
npm install
npm test          # runs security.test.ts via tsx
npm run typecheck # tsc --noEmit
```

## Status Icon

- 🔒 `max` (default) - full protection
- 🟡 `basic` - redact only
- 🔓 `off` - no protection

## License

MIT — same as the inspiring [`@raquezha/noleaks`](https://pi.dev/packages/@raquezha/noleaks).
