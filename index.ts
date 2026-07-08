/**
 * noleaks-personal - Personal noleaks extension for pi.dev
 *
 * Inspired by [@raquezha/noleaks](https://pi.dev/packages/@raquezha/noleaks).
 *
 * Protects sensitive paths from access and redacts secrets from tool output.
 * Modes:
 *   - max (default): Block sensitive paths AND redact secrets from output
 *   - basic: Allow reads but still redact secrets from output (Safe Debugging)
 *   - off: Disable all protection
 *
 * Security layers (defense-in-depth, ported from @raquezha/noleaks):
 *   - Symlink guard: paths are resolved to their real location before checks.
 *   - Obfuscation detection: NFKC normalization variance + hidden/control chars.
 *   - Env-dump block: `env`/`printenv`/`set`/`export` in shell commands.
 *   - Sensitive shell expansion: `$TOKEN`, `$SECRET`, `$PASSWORD`, etc.
 *   - Transform+smuggle: base64/openssl/gpg piping secret-looking material.
 *   - Discovery/exfil combine: nmap/curl/nc + sensitive material.
 *   - Universal word scan: critical utilities as arguments (sudo chmod, dd, shred).
 *   - Write/edit payload scan: blocks writes containing secret-looking material.
 *   - grep/find/ls guard: blocks these tools over sensitive paths in max mode.
 *   - Persistence: mode survives sessions via ~/.pi/agent/noleaks.json.
 *
 * Usage:
 *   /noleaks              - Show session statistics
 *   /noleaks mode max     - Switch to MAX mode
 *   /noleaks mode basic   - Switch to BASIC mode
 *   /noleaks mode off     - Switch to OFF mode (DANGEROUS)
 */

import { homedir } from "node:os";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type {
  BashToolInput,
  ExtensionAPI,
  ExtensionContext,
  ReadToolInput,
  ToolCallEvent,
  ToolResultEvent,
  WriteToolInput,
} from "@earendil-works/pi-coding-agent";

import {
  checkBashExfil,
  checkBashWords,
  checkEgressSecrets,
  checkObfuscation,
  checkPathSensitivity,
  detectInjection,
  hasSecretMaterial,
  isTaintedEgress,
  redactSecretsInText,
  resolvePath,
  type RedactStats,
} from "./security.js";

// ============================================================================
// Types
// ============================================================================

type Mode = "max" | "basic" | "off";

interface SessionStats extends RedactStats {
  blockedCalls: number;
  redactedSecrets: number;
  startTime: number;
  blockedByCategory: Record<string, number>;
}

interface ExtensionState {
  mode: Mode;
  yolo: boolean;
  taintedPaths: Set<string>;
  stats: SessionStats;
}

interface ToolCallResult {
  block?: boolean;
  reason?: string;
}

// ============================================================================
// Constants
// ============================================================================

const EXTENSION_NAME = "noleaks-personal";
const DEFAULT_MODE: Mode = "max";
const STATUS_KEY = "noleaks-mode";
const CONFIG_PATH = join(homedir(), ".pi", "agent", "noleaks.json");

// Shell commands that read files
const FILE_READ_COMMANDS = new Set([
  "cat", "less", "more", "head", "tail", "type", "bat",
  "grep", "rg", "ag", "ack",
  "source", ".",
]);

// Shell commands that write files
const FILE_WRITE_COMMANDS = new Set([
  "tee", "cp", "copy", "mv", "move", "install",
  "touch", "truncate", "dd",
]);

// Shell commands that delete files
const FILE_DELETE_COMMANDS = new Set([
  "rm", "unlink", "shred", "srm", "del", "erase", "trash",
]);

// ============================================================================
// Utility functions
// ============================================================================

function getModeIcon(mode: Mode): string {
  switch (mode) {
    case "max": return "🔒";
    case "basic": return "🟡";
    case "off": return "🔓";
  }
}

function getModeLabel(mode: Mode): string {
  switch (mode) {
    case "max": return "noLeak MAX";
    case "basic": return "noLeak BASIC";
    case "off": return "noLeak OFF";
  }
}

function extractPathsFromCommand(command: string): string[] {
  const tokenRegex = /(['"])([^'"]+)\1|(\S+)/g;
  const paths: string[] = [];
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(command)) !== null) {
    const token = match[2] ?? match[3] ?? "";
    if (token.startsWith("-")) continue;
    if (["|", "&&", "||", ">>", ">", "<", "<<", ";"].includes(token)) continue;
    paths.push(token);
  }

  return paths;
}

function getShellCommandName(command: string): string {
  const tokens = command.trim().split(/\s+/);
  for (const token of tokens) {
    if (!token.startsWith("-") && !["|", "&&", "||", ";"].includes(token)) {
      const parts = token.split("/");
      return (parts[parts.length - 1] ?? token).toLowerCase();
    }
  }
  return "";
}

// ============================================================================
// Persistence (ported from @raquezha/noleaks)
// ============================================================================

function loadConfig(): Mode {
  try {
    if (existsSync(CONFIG_PATH)) {
      const config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
      if (config.mode === "max" || config.mode === "basic" || config.mode === "off") {
        return config.mode;
      }
    }
  } catch {
    // ignore unreadable config
  }
  return DEFAULT_MODE;
}

function saveConfig(mode: Mode): void {
  try {
    const dir = join(homedir(), ".pi", "agent");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify({ mode }), "utf8");
  } catch {
    // ignore unwritable config
  }
}

// ============================================================================
// Extension
// ============================================================================

export default function noleaksPersonal(pi: ExtensionAPI): void {
  const state: ExtensionState = {
    mode: loadConfig(),
    yolo: false,
    taintedPaths: new Set<string>(),
    stats: {
      blockedCalls: 0,
      redactedSecrets: 0,
      startTime: Date.now(),
      blockedByCategory: {},
      redactedByPattern: {},
    },
  };

  // ──────────────────────────────────────────────────────────────────────────
  // UI helpers
  // ──────────────────────────────────────────────────────────────────────────

  const updateStatus = (ctx: ExtensionContext): void => {
    if (!ctx.hasUI) return;
    ctx.ui.setStatus(STATUS_KEY, `${getModeIcon(state.mode)} ${getModeLabel(state.mode)}`);
  };

  const notify = (ctx: ExtensionContext, message: string, level: "info" | "warning" | "error" = "info"): void => {
    if (!ctx.hasUI) return;
    ctx.ui.notify(message, level);
  };

  const setMode = (ctx: ExtensionContext, newMode: Mode): void => {
    state.mode = newMode;
    saveConfig(newMode);
    updateStatus(ctx);
  };

  /**
   * Ask the user before blocking. In YOLO mode, never blocks (but redaction
   * still applies at tool_result). This keeps the agent useful: the user
   * decides per-session whether to allow sensitive operations.
   */
  const confirmBlock = async (
    ctx: ExtensionContext,
    title: string,
    body: string,
    category: string
  ): Promise<boolean> => {
    if (state.yolo) return true; // YOLO: allow without asking
    recordBlock(category);
    const ok = await ctx.ui.confirm(title, body);
    if (!ok) return false; // user denied → keep blocked
    unrecordBlock(category);
    return true; // user allowed → proceed
  };

  const formatStats = (): string => {
    const duration = Math.floor((Date.now() - state.stats.startTime) / 1000);
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;

    const lines: string[] = [];
    lines.push(`Mode: ${getModeLabel(state.mode)}`);
    lines.push(`Session duration: ${minutes}m ${seconds}s`);
    lines.push(`Blocked tool calls: ${state.stats.blockedCalls}`);
    lines.push(`Redacted secrets: ${state.stats.redactedSecrets}`);

    if (Object.keys(state.stats.blockedByCategory).length > 0) {
      lines.push("\nBlocked by category:");
      for (const [cat, cnt] of Object.entries(state.stats.blockedByCategory)) {
        lines.push(`  ${cat}: ${cnt}`);
      }
    }

    if (Object.keys(state.stats.redactedByPattern).length > 0) {
      lines.push("\nRedacted by pattern:");
      for (const [pat, cnt] of Object.entries(state.stats.redactedByPattern)) {
        lines.push(`  ${pat}: ${cnt}`);
      }
    }

    return lines.join("\n");
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Path sensitivity checker
  // ──────────────────────────────────────────────────────────────────────────

  const recordBlock = (category: string): void => {
    state.stats.blockedCalls++;
    state.stats.blockedByCategory[category] = (state.stats.blockedByCategory[category] ?? 0) + 1;
  };

  const unrecordBlock = (category: string): void => {
    state.stats.blockedCalls--;
    const current = state.stats.blockedByCategory[category] ?? 0;
    if (current > 0) {
      state.stats.blockedByCategory[category] = current - 1;
    }
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Read guard
  // ──────────────────────────────────────────────────────────────────────────

  const guardReadPath = async (
    path: string,
    ctx: ExtensionContext
  ): Promise<ToolCallResult> => {
    const fullPath = resolvePath(ctx.cwd, path);
    const check = checkPathSensitivity(fullPath);

    if (!check.matched) return {};
    if (state.mode !== "max") return {}; // basic and off: allow reads

    const ok = await confirmBlock(
      ctx,
      "⚠️ Sensitive File Access",
      `noleaks: attempt to read sensitive file:\n\n  ${path}\n\nCategory: ${check.pattern!.category}\nPattern: ${check.pattern!.name}\n\nAllow this read?`,
      check.pattern!.category
    );

    if (!ok) {
      return {
        block: true,
        reason: `Blocked by ${EXTENSION_NAME}: read of sensitive path '${path}' (${check.pattern!.category})`,
      };
    }

    return {};
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Write guard (max mode only)
  // ──────────────────────────────────────────────────────────────────────────

  const guardWritePath = async (
    path: string,
    ctx: ExtensionContext
  ): Promise<ToolCallResult> => {
    const fullPath = resolvePath(ctx.cwd, path);
    const check = checkPathSensitivity(fullPath);

    if (!check.matched) return {};
    if (state.mode !== "max") return {};

    const ok = await confirmBlock(
      ctx,
      "⚠️ Sensitive File Write",
      `noleaks: attempt to write to sensitive file:\n\n  ${path}\n\nCategory: ${check.pattern!.category}\n\nAllow this write?`,
      check.pattern!.category
    );

    if (!ok) {
      return {
        block: true,
        reason: `Blocked by ${EXTENSION_NAME}: write to sensitive path '${path}' (${check.pattern!.category})`,
      };
    }
    return {};
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Bash guard
  // ──────────────────────────────────────────────────────────────────────────

  const guardBashCommand = async (
    input: BashToolInput,
    ctx: ExtensionContext
  ): Promise<ToolCallResult> => {
    const commandName = getShellCommandName(input.command);

    // Check reads
    if (FILE_READ_COMMANDS.has(commandName) && state.mode === "max") {
      const paths = extractPathsFromCommand(input.command);
      for (const p of paths) {
        const fullPath = resolvePath(ctx.cwd, p);
        const check = checkPathSensitivity(fullPath);
        if (!check.matched) continue;

        recordBlock(check.pattern!.category);

        const ok = await ctx.ui.confirm(
          "⚠️ Sensitive File Access via Shell",
          `noleaks: blocked ${commandName} on sensitive file:\n\n  ${p}\n\nCategory: ${check.pattern!.category}\n\nAllow?`
        );

        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: shell command '${commandName}' reads sensitive path '${p}'`,
          };
        }

        unrecordBlock(check.pattern!.category);
      }
    }

    // Check writes (max mode only)
    if (FILE_WRITE_COMMANDS.has(commandName) && state.mode === "max") {
      const paths = extractPathsFromCommand(input.command);
      for (const p of paths) {
        const fullPath = resolvePath(ctx.cwd, p);
        const check = checkPathSensitivity(fullPath);
        if (!check.matched) continue;

        const ok = await confirmBlock(
          ctx,
          "⚠️ Sensitive File Write via Shell",
          `noleaks: ${commandName} attempts to write to sensitive file:\n\n  ${p}\n\nCategory: ${check.pattern!.category}\n\nAllow?`,
          check.pattern!.category
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: shell command '${commandName}' writes to sensitive path '${p}'`,
          };
        }
      }
    }

    // Check deletes (max mode only)
    if (FILE_DELETE_COMMANDS.has(commandName) && state.mode === "max") {
      const paths = extractPathsFromCommand(input.command);
      for (const p of paths) {
        if (p === "-rf" || p === "-f" || p === "-r" || p === "-fr") continue;

        const fullPath = resolvePath(ctx.cwd, p);
        const check = checkPathSensitivity(fullPath);
        if (!check.matched) continue;

        const ok = await confirmBlock(
          ctx,
          "⚠️ Sensitive File Delete",
          `noleaks: ${commandName} attempts to delete sensitive file:\n\n  ${p}\n\nCategory: ${check.pattern!.category}\n\nAllow?`,
          check.pattern!.category
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: shell command '${commandName}' deletes sensitive path '${p}'`,
          };
        }
      }
    }

    // --- Ported + 2026 security layers ---
    // Obfuscation (max only)
    const obfuscation = checkObfuscation(input.command);
    if (obfuscation && state.mode === "max") {
      const ok = await confirmBlock(ctx, "⚠️ Obfuscated Command", `noleaks: ${obfuscation}\n\nCommand will be blocked unless you allow it.\n\nAllow?`, "Obfuscation");
      if (!ok) return { block: true, reason: `Blocked by ${EXTENSION_NAME}: ${obfuscation}` };
    }

    // Egress DLP (2026): secret in network egress
    const egress = checkEgressSecrets(input.command);
    if (egress) {
      const ok = await confirmBlock(ctx, "⚠️ Egress DLP", `noleaks: ${egress}\n\nCommand will be blocked unless you allow it.\n\nAllow?`, "Egress DLP");
      if (!ok) return { block: true, reason: `Blocked by ${EXTENSION_NAME}: ${egress}` };
    }

    // Env-dump / sensitive expansion / transform-smuggle / discovery-exfil
    const exfil = checkBashExfil(input.command);
    if (exfil && (state.mode === "max" || exfil.includes("secret") || exfil.includes("environment"))) {
      const ok = await confirmBlock(ctx, "⚠️ Exfiltration Risk", `noleaks: ${exfil}\n\nCommand will be blocked unless you allow it.\n\nAllow?`, "Exfiltration");
      if (!ok) return { block: true, reason: `Blocked by ${EXTENSION_NAME}: ${exfil}` };
    }

    // Critical utilities / sensitive path references in args
    const words = checkBashWords(input.command, ctx.cwd, state.mode);
    if (words && state.mode === "max") {
      const ok = await confirmBlock(ctx, "⚠️ Risky Command", `noleaks: ${words}\n\nCommand will be blocked unless you allow it.\n\nAllow?`, "Command Scan");
      if (!ok) return { block: true, reason: `Blocked by ${EXTENSION_NAME}: ${words}` };
    }

    return {};
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Result redactor
  // ──────────────────────────────────────────────────────────────────────────

  const redactToolResult = (
    event: ToolResultEvent
  ): { content: typeof event.content; details?: Record<string, unknown> } | undefined => {
    if (state.mode === "off") return undefined;
    if (!event.content || !Array.isArray(event.content)) return undefined;

    let totalRedacted = 0;
    let contentChanged = false;
    const newContent = event.content.map((block) => {
      if (block.type !== "text") return block;
      const textBlock = block as { type: "text"; text: string };

      const result = redactSecretsInText(textBlock.text, state.stats);
      if (result.count > 0) {
        totalRedacted += result.count;
        contentChanged = true;
        return { ...textBlock, text: result.text };
      }
      return block;
    });

    if (contentChanged) {
      state.stats.redactedSecrets += totalRedacted;
      return {
        content: newContent,
        details: { ...(event.details as Record<string, unknown> | undefined ?? {}), noleaksRedacted: totalRedacted },
      };
    }

    return undefined;
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Event handlers
  // ──────────────────────────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    // Reset per-session stats but keep persisted mode
    state.stats = {
      blockedCalls: 0,
      redactedSecrets: 0,
      startTime: Date.now(),
      blockedByCategory: {},
      redactedByPattern: {},
    };
    updateStatus(ctx);
    notify(ctx, `🛡️ ${EXTENSION_NAME} loaded (mode: ${state.mode})`, "info");
  });

  pi.on("session_shutdown", async () => {
    // Cleanup if needed
  });

  pi.on("tool_call", async (event, ctx) => {
    if (state.mode === "off") return undefined;
    const e = event as ToolCallEvent;

    if (e.toolName === "bash") {
      return await guardBashCommand(e.input as BashToolInput, ctx);
    }

    if (e.toolName === "read") {
      const path = (e.input as ReadToolInput).path;
      const result = await guardReadPath(path, ctx);
      // Taint tracking (2026): remember sensitive reads so egress is blocked later
      if (!result.block && state.mode === "max") {
        const fullPath = resolvePath(ctx.cwd, path);
        if (checkPathSensitivity(fullPath).matched) {
          state.taintedPaths.add(fullPath);
        }
      }
      return result;
    }

    if (e.toolName === "write" || e.toolName === "edit") {
      const writeResult = await guardWritePath((e.input as WriteToolInput).path, ctx);
      if (writeResult.block) return writeResult;
      // Block writes whose payload contains secret-looking material
      if (state.mode === "max" && hasSecretMaterial(e.input)) {
        const ok = await confirmBlock(
          ctx,
          "⚠️ Secret in Write Payload",
          "noleaks: write/edit payload contains secret-looking material.\n\nAllow this write?",
          "Secret Payload"
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: write/edit payload contains secret-looking material`,
          };
        }
      }
      // Taint egress: if writing tainted content to a non-sensitive path, block
      if (state.mode === "max" && isTaintedEgress(e.toolName, e.input, state.taintedPaths)) {
        const ok = await confirmBlock(
          ctx,
          "⚠️ Tainted Egress",
          "noleaks: write references content previously read from a sensitive path.\n\nAllow this write?",
          "Taint Egress"
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: write references tainted sensitive content`,
          };
        }
      }
      return writeResult;
    }

    // grep / find / ls guards over sensitive paths (max mode)
    if ((e.toolName === "grep" || e.toolName === "find" || e.toolName === "ls") && state.mode === "max") {
      const pathArg = (e.input as { path?: string }).path;
      if (pathArg) {
        const check = checkPathSensitivity(resolvePath(ctx.cwd, pathArg));
        if (check.matched) {
          const ok = await confirmBlock(
            ctx,
            "⚠️ Sensitive Path Scan",
            `noleaks: ${e.toolName} over sensitive path '${pathArg}' (${check.pattern!.category}).\n\nAllow?`,
            check.pattern!.category
          );
          if (!ok) {
            return {
              block: true,
              reason: `Blocked by ${EXTENSION_NAME}: ${e.toolName} over sensitive path '${pathArg}' (${check.pattern!.category})`,
            };
          }
        }
      }
      if (hasSecretMaterial(e.input)) {
        const ok = await confirmBlock(
          ctx,
          "⚠️ Secret in Query",
          `noleaks: ${e.toolName} payload references secret-looking material.\n\nAllow?`,
          "Secret Payload"
        );
        if (!ok) {
          return {
            block: true,
            reason: `Blocked by ${EXTENSION_NAME}: ${e.toolName} payload references secret-looking material`,
          };
        }
      }
    }

    return undefined;
  });

  pi.on("tool_result", async (event, ctx) => {
    const e = event as ToolResultEvent;

    // Injection detection (2026): scan tool results for embedded injection attempts
    if (state.mode !== "off" && e.content && Array.isArray(e.content)) {
      for (const block of e.content) {
        if (block.type !== "text") continue;
        const textBlock = block as { type: "text"; text: string };
        const inj = detectInjection(textBlock.text);
        if (inj.high.length > 0) {
          notify(
            ctx,
            `🚨 noleaks: potential prompt-injection in ${e.toolName} output [${inj.high.join(", ")}]. Review before trusting.`,
            "warning"
          );
        } else if (inj.low.length > 0 && !state.yolo) {
          notify(
            ctx,
            `⚠️ noleaks: suspicious phrasing in ${e.toolName} output [${inj.low.join(", ")}]. Possible injection.`,
            "info"
          );
        }
      }
    }

    const result = redactToolResult(e);
    if (result && state.mode === "max" && ((result.details?.noleaksRedacted as number) ?? 0) > 0) {
      notify(ctx, `🛡️ noleaks: redacted ${(result.details?.noleaksRedacted as number) ?? 0} secret(s) from ${e.toolName} output`, "info");
    }
    return result as { content?: typeof e.content; details?: unknown } | undefined;
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Commands
  // ──────────────────────────────────────────────────────────────────────────

  pi.registerCommand("noleaks", {
    description: `Manage ${EXTENSION_NAME} protection (current mode: ${state.mode})`,
    handler: async (args, ctx) => {
      const trimmed = args.trim();

      if (trimmed === "" || trimmed === "status") {
        notify(ctx, formatStats(), "info");
        return;
      }

      const modeMatch = trimmed.match(/^mode\s+(max|basic|off)$/i);
      if (modeMatch) {
        const newMode = modeMatch[1]!.toLowerCase() as Mode;
        setMode(ctx, newMode);

        const messages: Record<Mode, string> = {
          max: `${getModeIcon("max")} ${EXTENSION_NAME}: MAX mode - blocks sensitive paths AND redacts secrets`,
          basic: `${getModeIcon("basic")} ${EXTENSION_NAME}: BASIC mode - allows reads but still redacts secrets`,
          off: `${getModeIcon("off")} ${EXTENSION_NAME}: OFF mode - all protection disabled (DANGEROUS)`,
        };

        notify(ctx, messages[newMode], newMode === "off" ? "warning" : "info");
        return;
      }

      // YOLO: skip confirm prompts for this session (redaction still applies)
      if (trimmed === "yolo" || trimmed === "yolo on") {
        state.yolo = true;
        notify(ctx, `🔥 ${EXTENSION_NAME}: YOLO mode ON - blocks will ask, but you can allow per-session. Redaction still active.`, "warning");
        return;
      }
      if (trimmed === "yolo off") {
        state.yolo = false;
        notify(ctx, `🔒 ${EXTENSION_NAME}: YOLO mode OFF - confirm prompts restored.`, "info");
        return;
      }

      // Help
      notify(
        ctx,
        `${EXTENSION_NAME} commands:\n` +
        `  /noleaks              - Show session statistics\n` +
        `  /noleaks mode max     - Block sensitive paths AND redact secrets\n` +
        `  /noleaks mode basic   - Allow reads, still redact secrets\n` +
        `  /noleaks mode off     - Disable all protection\n` +
        `  /noleaks yolo         - Skip confirm prompts this session (redaction stays on)`,
        "info"
      );
    },
  });

  // Initial status set
  pi.on("session_start", async (_event, ctx) => {
    updateStatus(ctx);
  });
}
