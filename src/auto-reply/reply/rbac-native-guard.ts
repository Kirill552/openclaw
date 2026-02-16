/**
 * RBAC native command guard — shared helper for fork modifications.
 * Reads RBAC plugin config from openclaw.json and checks:
 * 1. Is the sender an admin?
 * 2. Is the command blocked for non-admin users by systemCommands?
 *
 * This file is part of the REQUIRED fork modifications for RBAC.
 * Without these changes, built-in commands (/status, /compact, /stop, /config, etc.)
 * bypass the RBAC plugin's before_tool_call hook entirely.
 *
 * Used by:
 * - abort.ts              — skip fast-abort for non-admin /stop (universal, all channels)
 * - commands-core.ts      — block/allow system commands for non-admin (universal, all channels)
 * - bot-native-commands.ts — block native Telegram commands for non-admin (Telegram only)
 */
import type { OpenClawConfig } from "../../config/config.js";

export interface RbacCommandCheck {
  /** Whether sender is in the admin role's users list */
  isAdmin: boolean;
  /** Whether this command is blocked for the sender */
  blocked: boolean;
  /** Response text to send when blocked (null if not blocked) */
  response: string | null;
}

/**
 * Check if a command should be blocked by RBAC systemCommands config.
 *
 * @returns { isAdmin: true, blocked: false } if no RBAC config exists (backwards compatible).
 */
export function checkRbacCommand(params: {
  cfg: OpenClawConfig;
  senderId: string;
  command: string; // e.g., "/stop", "/compact", "/status"
}): RbacCommandCheck {
  const { cfg, senderId, command } = params;

  // Navigate: plugins.entries.rbac.config
  const pluginsCfg = (cfg as unknown as Record<string, unknown>).plugins as
    | Record<string, unknown>
    | undefined;
  const entries = pluginsCfg?.entries as Record<string, unknown> | undefined;
  const rbacPlugin = entries?.rbac as Record<string, unknown> | undefined;
  const rbacConfig = rbacPlugin?.config as Record<string, unknown> | undefined;

  // No RBAC config → everything allowed (backwards compatible)
  if (!rbacConfig?.roles) {
    return { isAdmin: true, blocked: false, response: null };
  }

  // Check admin role
  const adminRole = (rbacConfig.roles as Record<string, unknown>)?.admin as
    | Record<string, unknown>
    | undefined;
  const adminUsers = adminRole?.users;
  const isAdmin =
    Array.isArray(adminUsers) && adminUsers.includes(String(senderId));

  if (isAdmin) {
    return { isAdmin: true, blocked: false, response: null };
  }

  // Non-admin: check systemCommands
  const sysCmds = rbacConfig.systemCommands as
    | Record<string, unknown>
    | undefined;
  if (!sysCmds) {
    // No systemCommands config → commands not guarded (only tools are guarded)
    return { isAdmin: false, blocked: false, response: null };
  }

  const mode = (sysCmds.mode as string) ?? "blocklist";
  const cmdLower = command.toLowerCase();
  let blocked = false;

  if (mode === "allowlist") {
    const allowed = (
      Array.isArray(sysCmds.allowed) ? sysCmds.allowed : []
    ) as string[];
    blocked = !allowed.includes(cmdLower);
  } else {
    const blockedList = (
      Array.isArray(sysCmds.blocked) ? sysCmds.blocked : []
    ) as string[];
    blocked = blockedList.includes(cmdLower);
  }

  // /help always intercepted when guestHelp is configured
  if (cmdLower === "/help" && sysCmds.guestHelp) {
    blocked = true;
  }

  if (!blocked) {
    return { isAdmin: false, blocked: false, response: null };
  }

  // Determine response text
  const response =
    cmdLower === "/help" && sysCmds.guestHelp
      ? String(sysCmds.guestHelp)
      : String(sysCmds.blockResponse ?? "Command not available.");

  return { isAdmin: false, blocked: true, response };
}
