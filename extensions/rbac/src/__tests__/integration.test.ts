import { describe, it, expect } from "vitest";
import { rbacConfigSchema, type RBACConfig } from "../config.js";
import { parseSessionKey } from "../session-key-parser.js";
import { resolveRole } from "../role-resolver.js";
import { checkToolAccess } from "../tool-guard.js";
import { matchBlockedCommand, getBlockResponse, isAdminByTools } from "../command-guard.js";

// ---------------------------------------------------------------------------
// Helper: simulate what the before_tool_call hook does end-to-end
// ---------------------------------------------------------------------------
type SimResult =
  | { action: "allow"; role: string }
  | { action: "block"; reason: string }
  | { action: "skip" } // no sessionKey or parsed is null & failSafe=allow
  | { action: "failsafe-deny" };

function simulateHook(
  sessionKey: string | null,
  toolName: string,
  config: RBACConfig,
): SimResult {
  // No session context — allow (internal/system call)
  if (!sessionKey) return { action: "skip" };

  const parsed = parseSessionKey(sessionKey);

  // Can't determine sender — check failSafe
  if (!parsed) {
    if (config.failSafe === "deny") {
      return { action: "failsafe-deny" };
    }
    return { action: "skip" };
  }

  const { peerId, channel } = parsed;
  const roleName = resolveRole(peerId, channel, config);
  const result = checkToolAccess(toolName, roleName, config);

  if (!result.allowed) {
    return {
      action: "block",
      reason: result.reason ?? "Access denied by RBAC policy",
    };
  }

  return { action: "allow", role: roleName };
}

// ---------------------------------------------------------------------------
// Shared config: Sarapul-style with channel-specific guest roles
// ---------------------------------------------------------------------------
const sarapulRawConfig = {
  roles: {
    admin: {
      users: ["408001372", "447903128"],
      tools: "*",
      channels: "*",
    },
    "guest-telegram": {
      users: "*",
      tools: ["get_recent_news", "subscribe_user", "unsubscribe_user"],
      channels: ["telegram"],
    },
    "guest-max": {
      users: "*",
      tools: ["get_recent_news", "subscribe_user", "unsubscribe_user", "memory_search"],
      channels: ["max"],
    },
    guest: {
      users: "*",
      tools: ["get_recent_news"],
      channels: "*",
    },
  },
  defaultRole: "guest",
  logBlocked: true,
  logAllowed: true,
  failSafe: "deny",
};

const sarapulConfig = rbacConfigSchema.parse(sarapulRawConfig);

// ===========================================================================
// Group 1 — Admin full access
// ===========================================================================
describe("integration — admin full access", () => {
  it("admin in telegram can use exec", () => {
    // per-channel-peer: agent:main:telegram:direct:408001372
    const result = simulateHook(
      "agent:main:telegram:direct:408001372",
      "exec",
      sarapulConfig,
    );
    expect(result).toEqual({ action: "allow", role: "admin" });
  });

  it("admin in max can use browser", () => {
    // per-channel-peer: agent:main:max:direct:447903128
    const result = simulateHook(
      "agent:main:max:direct:447903128",
      "browser",
      sarapulConfig,
    );
    expect(result).toEqual({ action: "allow", role: "admin" });
  });
});

// ===========================================================================
// Group 2 — Guest channel-specific access
// ===========================================================================
describe("integration — guest channel-specific", () => {
  it("telegram guest can subscribe", () => {
    const result = simulateHook(
      "agent:main:telegram:direct:999111222",
      "subscribe_user",
      sarapulConfig,
    );
    expect(result).toEqual({ action: "allow", role: "guest-telegram" });
  });

  it("telegram guest cannot use memory_search", () => {
    const result = simulateHook(
      "agent:main:telegram:direct:999111222",
      "memory_search",
      sarapulConfig,
    );
    expect(result.action).toBe("block");
  });

  it("max guest CAN use memory_search", () => {
    const result = simulateHook(
      "agent:main:max:direct:999111222",
      "memory_search",
      sarapulConfig,
    );
    expect(result).toEqual({ action: "allow", role: "guest-max" });
  });

  it("max guest cannot use exec", () => {
    const result = simulateHook(
      "agent:main:max:direct:999111222",
      "exec",
      sarapulConfig,
    );
    expect(result.action).toBe("block");
  });
});

// ===========================================================================
// Group 3 — Unknown channel fallback
// ===========================================================================
describe("integration — unknown channel fallback", () => {
  it("web-chat guest gets generic guest role", () => {
    // A user from an unknown channel "web" — should fall through to generic guest
    const result = simulateHook(
      "agent:main:web:direct:555666777",
      "get_recent_news",
      sarapulConfig,
    );
    expect(result).toEqual({ action: "allow", role: "guest" });
  });

  it("generic guest is limited to get_recent_news only", () => {
    // Generic guest should NOT have subscribe_user (only channel-specific guests have it)
    const result = simulateHook(
      "agent:main:web:direct:555666777",
      "subscribe_user",
      sarapulConfig,
    );
    expect(result.action).toBe("block");
  });
});

// ===========================================================================
// Group 4 — Fail-safe deny / allow
// ===========================================================================
describe("integration — fail-safe behavior", () => {
  it("blocks on unrecognized sessionKey when failSafe=deny", () => {
    // "main" scope key — too short, parseSessionKey returns null
    const denyConfig = rbacConfigSchema.parse({
      ...sarapulRawConfig,
      failSafe: "deny",
    });
    const result = simulateHook("agent:main:main", "exec", denyConfig);
    expect(result.action).toBe("failsafe-deny");
  });

  it("allows on unrecognized sessionKey when failSafe=allow", () => {
    const allowConfig = rbacConfigSchema.parse({
      ...sarapulRawConfig,
      failSafe: "allow",
    });
    const result = simulateHook("agent:main:main", "exec", allowConfig);
    expect(result.action).toBe("skip");
  });
});

// ===========================================================================
// Group 5 — Config validation through rbacConfigSchema.parse
// ===========================================================================
describe("integration — config parsing validates end-to-end", () => {
  it("parsed config has expected warnings for empty tools", () => {
    const cfg = rbacConfigSchema.parse({
      roles: {
        locked: { users: ["u1"], tools: [], channels: "*" },
        guest: { users: "*", tools: ["help"], channels: "*" },
      },
      defaultRole: "guest",
    });
    expect(cfg.warnings).toContain(
      'Role "locked" has empty tools array \u2014 it will block all tool access.',
    );
  });
});

// ===========================================================================
// Group 6 — System command guard (allowlist mode, end-to-end)
// ===========================================================================
describe("integration — system command guard (allowlist)", () => {
  const configWithGuard = rbacConfigSchema.parse({
    ...sarapulRawConfig,
    systemCommands: {
      mode: "allowlist",
      allowed: ["/start", "/stop", "/news"],
      guestHelp: "Я бот. /news — новости, /start — подписка, /stop — отписка.",
      blockResponse: "Команда недоступна. /help для списка команд.",
    },
  });
  const sysCmds = configWithGuard.systemCommands!;

  it("guest sending /status → blocked, returns blockResponse", () => {
    const sessionKey = "agent:main:telegram:direct:999111222";
    const parsed = parseSessionKey(sessionKey)!;
    const roleName = resolveRole(parsed.peerId, parsed.channel, configWithGuard);
    const isAdmin = isAdminByTools(roleName, configWithGuard.roles);
    expect(isAdmin).toBe(false);

    const cmd = matchBlockedCommand("/status", sysCmds);
    expect(cmd).toBe("/status");

    const response = getBlockResponse(cmd!, sysCmds);
    expect(response).toBe("Команда недоступна. /help для списка команд.");
  });

  it("guest sending /help → intercepted, returns guestHelp", () => {
    const cmd = matchBlockedCommand("/help", sysCmds);
    expect(cmd).toBe("/help");
    expect(getBlockResponse(cmd!, sysCmds)).toBe(
      "Я бот. /news — новости, /start — подписка, /stop — отписка.",
    );
  });

  it("guest sending /start → allowed (in allowed list)", () => {
    const cmd = matchBlockedCommand("/start", sysCmds);
    expect(cmd).toBeNull();
  });

  it("guest sending /config → blocked (not in allowed list)", () => {
    const cmd = matchBlockedCommand("/config", sysCmds);
    expect(cmd).toBe("/config");
  });

  it("guest sending /exec → blocked (not in allowed list)", () => {
    const cmd = matchBlockedCommand("/exec", sysCmds);
    expect(cmd).toBe("/exec");
  });

  it("admin sending /status → NOT blocked (admin bypass)", () => {
    const sessionKey = "agent:main:telegram:direct:408001372";
    const parsed = parseSessionKey(sessionKey)!;
    const roleName = resolveRole(parsed.peerId, parsed.channel, configWithGuard);
    const isAdmin = isAdminByTools(roleName, configWithGuard.roles);
    expect(isAdmin).toBe(true);
    // Admin → skip command guard entirely
  });

  it("regular text from guest → not intercepted", () => {
    const cmd = matchBlockedCommand("привет, какие новости?", sysCmds);
    expect(cmd).toBeNull();
  });
});
