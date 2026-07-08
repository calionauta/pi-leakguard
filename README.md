# pi-leakguard

I built this **leakguard** extension for [pi.dev](https://pi.dev) as a defense-in-depth
"seatbelt" that keeps my coding agent from reading/writing/exfiltrating my credentials, and
redacts secrets from tool output before the model ever sees them.

> **Inspired by `@raquezha/noleaks`** (MIT, by raquezha, published on npm/pi.dev). I kept that
> project's original security layers and added a richer redaction set, interactive
> confirmation on every block, detailed session stats, and mode persistence.
> Credit for the core bash-security logic (symlink guard, obfuscation detection,
> env-dump/sensitive-expansion blocks, transform-smuggle, discovery/exfil combine,
> universal word scan, write-payload scan, grep/find/ls guards, and `leakguard.json`
> persistence) goes to raquezha.
>
> **Note:** this is my independent continuation of `@raquezha/noleaks`' ideas and security
> layers, not an official fork. I kept the MIT license and attribution.

> **Security model:** this is a powerful defense-in-depth
> "seatbelt", **not** an airtight sandbox. It stops accidental leaks and common AI
> exfiltration tricks. For untrusted code or unattended automation, use a real sandbox
> (Docker, Micro-VM) — don't rely on this alone.

## Security model & limitations

When a layer fires, here's what happens:

- **BLOCK** — leakguard stops the tool call (unless you allow it via the confirm prompt or `/leakguard yolo`).
- **REDACT** — leakguard replaces the secret text before the model sees it; the agent still knows a secret *exists*, just not its value.
- **WARN** — leakguard shows a notification; it doesn't block anything.

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
| Pre-commit/push scan | BLOCK (confirm) | Secret in `git diff` on commit/push | Low — scans diff, not whole tree | Medium — novel formats |
| Audit log | WARN (log only) | Every block/redact/allow event | None — observability | None |
| Extensible config | n/a | User allow/block paths + extra secret patterns | None — user-defined | None — user-defined |

### Why I don't try to detect prompt injection by pattern

Detecting prompt injection with regex/heuristics is **not a consolidated
industry strategy**. Attackers write injections in endless variations
(obfuscation, other languages, indirect phrasing like "the previous
instructions are deprecated"), so a fixed pattern list misses almost everything
and false-positives on normal prose ("ignore the previous section"). Maintaining
that list costs more than it's worth.

So instead of trying to *catch* the injection, I stop the **harm** it causes:

- If the model gets tricked into reading a secret, **redaction** strips it
  from what it can see and repeat.
- If it gets tricked into exfiltrating, **egress DLP** and **taint
  tracking** block the network call carrying credentials.

Think of leakguard as shrinking the blast radius, not as a detector.

### How I keep false positives / false negatives in check

- **I confirm, I don't silently block.** Every BLOCK asks you via `ctx.ui.confirm`
  (unless you run `/leakguard yolo`). I never silently disable the agent — you
  decide per case. This keeps the agent useful while still safe.
- **Conservative patterns.** leakguard's path and redaction patterns target specific
  file names and known secret prefixes; they avoid matching normal code.
- **YOLO mode** disables confirm prompts for a session but keeps REDACT on,
  so secrets still never reach the chat even when I skip blocks.
- **Redaction over blocking for output.** leakguard scrubs secrets from output
  instead of blocking it, which preserves agent utility (deploy still works via
  the environment) while preventing leakage — the preferred 2026 pattern of
  "don't give agents secrets".

## Features

- **Path protection**: leakguard blocks reads/writes/deletes of sensitive paths
  (`.env`, `~/.ssh/`, `~/.aws/`, `/etc/shadow`, Keychains, etc.)
- **Secret redaction**: leakguard scrubs API keys, tokens, passwords, private-key blocks,
  DB URLs, and secret assignments from `tool_result` content.
- **Symlink guard**: leakguard resolves paths to their *real* on-disk location before
  checking, so symlink bypasses are caught.
- **Obfuscation detection**: leakguard rejects NFKC normalization variance and hidden/control
  characters (homoglyph / zero-width attacks).
- **Shell exfiltration blocks**: leakguard blocks env dumps (`env`/`printenv`/`set`/`export`),
  sensitive variable expansion (`$TOKEN`), transform+smuggle (`base64`/`openssl`
  piping secrets), and discovery/exfil combine (`nmap`/`curl` + secrets).
- **Universal word scan**: leakguard blocks critical utilities even as nested arguments
  (`sudo chmod`, `dd`, `shred`, `mkfs`, ...).
- **Write/edit payload scan**: leakguard blocks writes whose body contains secret-looking
  material.
- **grep / find / ls guards**: leakguard blocks those tools over sensitive paths in
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
| `/leakguard yolo`      | Skip confirm prompts this session (redaction stays on) |

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
- 🔥 appended when `/leakguard yolo` is on (confirm prompts skipped; redaction stays on)

## License

MIT.
