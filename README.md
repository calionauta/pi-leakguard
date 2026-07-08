# pi-leakguard

Personal **leakguard** extension for [pi.dev](https://pi.dev) — a defense-in-depth
"seatbelt" that blocks the LLM from reading/writing/exfiltrating credentials and
redacts secrets from tool output before the model ever sees them.

> **Inspired by `@raquezha/noleaks`** (MIT, by raquezha). This project
> keeps the original's security layers and adds a richer redaction set, interactive
> confirmation on every block, detailed session stats, and mode persistence.
> Credit for the core bash-security logic (symlink guard, obfuscation detection,
> env-dump/sensitive-expansion blocks, transform-smuggle, discovery/exfil combine,
> universal word scan, write-payload scan, grep/find/ls guards, and `leakguard.json`
> persistence) goes to that project.
>
> **Note:** the original `@raquezha/noleaks` repository appears to have been
> removed from GitHub/npm. This project is an independent continuation that
> preserves and extends its ideas (not a fork, since the source repo is gone).
> The MIT license and attribution are retained.

> **Security model:** `leakguard` is a powerful defense-in-depth
> "seatbelt", **not** an airtight sandbox. It prevents accidental leaks and stops
> common AI exfiltration techniques. For untrusted code or unattended automation,
> always use a real sandbox (Docker, Micro-VM).

## Security model & limitations

Each layer below is classified by what it does when it fires:

- **BLOCK** — the tool call is stopped (unless you allow it via the confirm prompt or `/leakguard yolo`).
- **REDACT** — secret text is replaced before the model sees it; the agent still knows a secret *exists*, just not its value.
- **WARN** — a notification is shown; nothing is blocked.

| Layer | Action | What it catches | False-positive risk | False-negative risk |
| ----- | ------ | --------------- | ------------------ | ------------------ |
| Path protection (read/write/delete) | BLOCK (confirm) | Access to `.env`, `~/.ssh`, `/etc/shadow`, etc. | Low — patterns are specific file names | Medium — custom secret paths need manual config |
| Secret redaction (output) | REDACT | AWS/GitHub/Vault/1Password/DB-URL/etc. in tool output | Low — high-entropy + known prefixes | Medium — novel secret formats not in the pattern list |
| Symlink guard | BLOCK | Symlink bypass to a sensitive file | Very low | Low — `realpathSync` resolves before checking |
| Obfuscation (NFKC/control chars) | BLOCK | Homoglyph / zero-width bypass in commands | Low — normal whitespace is allowed | Low — only rejects clear variance |
| Shell exfil (env-dump, expansion, smuggle, discovery+secret) | BLOCK (confirm) | `env`, `$TOKEN`, `base64 \| curl`, `nmap`+secret | Low | Medium — arbitrarily obfuscated pipelines |
| Egress DLP | BLOCK (confirm) | `curl -u user:pass`, credentialed URLs, secret headers | Low — only fires on clear creds in egress | Medium — encoded/obfuscated payloads |
| Universal word scan | BLOCK (confirm) | `sudo chmod`, `dd`, `shred` as arguments | Low — only critical utils | Low | 
| Write/edit payload scan | BLOCK (confirm) | Secret material in write body | Low | Medium — novel formats |
| grep/find/ls guard | BLOCK (confirm) | These tools over sensitive paths | Low | Low |
| Taint tracking | BLOCK (confirm) | Egress of content read from a sensitive path | Low — only after a sensitive read | Medium — indirect leaks (e.g. summarizing then pasting) |

### Why we do NOT detect prompt injection by pattern

Prompt-injection detection by regex/heuristics is **not a consolidated
industry strategy**. Attackers write injections in endless variations
(obfuscation, other languages, indirect phrasing like "the previous
instructions are deprecated"), so a fixed pattern list has a **very high
false-negative rate** and produces false positives on legitimate prose
("ignore the previous section"). The cost of maintaining it outweighs the
value it delivers.

Instead, `leakguard` prevents the **harm** of an injection, not the injection
itself:

- Even if the model is tricked into reading a secret, **redaction** strips it
  from what the model can see and repeat.
- Even if the model is tricked into exfiltrating, **egress DLP** and **taint
  tracking** block the network call carrying credentials.

Treat `leakguard` as reducing blast radius, not as a detector.

### How false positives / false negatives are mitigated

- **Confirm, not silent block.** Every BLOCK asks you via `ctx.ui.confirm`
  (unless `/leakguard yolo`). The agent is never silently disabled — you
  decide per case. This keeps the agent useful while still safe.
- **Conservative patterns.** Path and redaction patterns target specific
  file names and known secret prefixes; they avoid matching normal code.
- **YOLO mode** disables confirm prompts for a session but keeps REDACT on,
  so secrets still never reach the chat even when blocks are skipped.
- **Redaction over blocking for output.** Scrubbing secrets from output
  preserves agent utility (deploy still works via the environment) while
  preventing leakage — the preferred 2026 pattern of "don't give agents
  secrets".

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
- **Three modes** (persisted to `~/.pi/agent/leakguard.json`):
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
| `/leakguard`           | Show session statistics (blocked, redacted)   |
| `/leakguard mode max`  | Block sensitive paths AND redact secrets      |
| `/leakguard mode basic`| Allow reads but still redact secrets          |
| `/leakguard mode off`  | Disable all protection (dangerous)            |

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
