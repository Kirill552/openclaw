import { describe, it, expect, beforeEach } from "vitest";
import {
  matchBlockedCommand,
  setPendingBlock,
  consumePendingBlock,
  getBlockResponse,
  isAdminByTools,
} from "../command-guard.js";
import type { SystemCommandsConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeBlocklist(overrides?: Partial<SystemCommandsConfig>): SystemCommandsConfig {
  return {
    mode: "blocklist",
    blocked: ["/status", "/whoami", "/context", "/model", "/commands"],
    allowed: [],
    guestHelp: "Guest help text",
    blockResponse: "I'm a bot. /help for commands",
    ...overrides,
  };
}

function makeAllowlist(overrides?: Partial<SystemCommandsConfig>): SystemCommandsConfig {
  return {
    mode: "allowlist",
    blocked: [],
    allowed: ["/start", "/stop", "/news"],
    guestHelp: "Guest help text",
    blockResponse: "I'm a bot. /help for commands",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// matchBlockedCommand — blocklist mode
// ---------------------------------------------------------------------------

describe("matchBlockedCommand (blocklist)", () => {
  const cfg = makeBlocklist();

  it("matches exact blocked command", () => {
    expect(matchBlockedCommand("/status", cfg)).toBe("/status");
  });

  it("matches blocked command with args", () => {
    expect(matchBlockedCommand("/model gpt-4", cfg)).toBe("/model");
  });

  it("matches case-insensitively", () => {
    expect(matchBlockedCommand("/Status", cfg)).toBe("/status");
    expect(matchBlockedCommand("/STATUS", cfg)).toBe("/status");
  });

  it("matches /help when guestHelp is configured", () => {
    expect(matchBlockedCommand("/help", cfg)).toBe("/help");
  });

  it("does NOT match /help when guestHelp is null", () => {
    const noHelp = makeBlocklist({ guestHelp: null });
    expect(matchBlockedCommand("/help", noHelp)).toBeNull();
  });

  it("matches /help even if not in blocked list", () => {
    const cfg2 = makeBlocklist({ blocked: ["/status"] });
    expect(matchBlockedCommand("/help", cfg2)).toBe("/help");
  });

  it("does NOT match non-blocked commands", () => {
    expect(matchBlockedCommand("/news", cfg)).toBeNull();
    expect(matchBlockedCommand("/start", cfg)).toBeNull();
  });

  it("does NOT match regular text", () => {
    expect(matchBlockedCommand("hello", cfg)).toBeNull();
    expect(matchBlockedCommand("what is status", cfg)).toBeNull();
  });

  it("does NOT match empty string", () => {
    expect(matchBlockedCommand("", cfg)).toBeNull();
  });

  it("handles leading whitespace", () => {
    expect(matchBlockedCommand("  /status", cfg)).toBe("/status");
  });

  it("does NOT match partial command names (blocklist uses exact command extraction)", () => {
    // "/statusbar" extracts command "/statusbar" which is NOT in blocked list
    expect(matchBlockedCommand("/statusbar", cfg)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// matchBlockedCommand — allowlist mode
// ---------------------------------------------------------------------------

describe("matchBlockedCommand (allowlist)", () => {
  const cfg = makeAllowlist();

  it("blocks any /command NOT in allowed list", () => {
    expect(matchBlockedCommand("/status", cfg)).toBe("/status");
    expect(matchBlockedCommand("/config", cfg)).toBe("/config");
    expect(matchBlockedCommand("/debug", cfg)).toBe("/debug");
    expect(matchBlockedCommand("/exec", cfg)).toBe("/exec");
    expect(matchBlockedCommand("/bash", cfg)).toBe("/bash");
    expect(matchBlockedCommand("/whoami", cfg)).toBe("/whoami");
    expect(matchBlockedCommand("/models", cfg)).toBe("/models");
    expect(matchBlockedCommand("/allowlist", cfg)).toBe("/allowlist");
  });

  it("allows commands in allowed list", () => {
    expect(matchBlockedCommand("/start", cfg)).toBeNull();
    expect(matchBlockedCommand("/stop", cfg)).toBeNull();
    expect(matchBlockedCommand("/news", cfg)).toBeNull();
  });

  it("allows commands in allowed list with args", () => {
    expect(matchBlockedCommand("/news москва", cfg)).toBeNull();
    expect(matchBlockedCommand("/start now", cfg)).toBeNull();
  });

  it("blocks unknown /commands with args", () => {
    expect(matchBlockedCommand("/config show", cfg)).toBe("/config");
    expect(matchBlockedCommand("/model gpt-4", cfg)).toBe("/model");
  });

  it("does NOT block regular text", () => {
    expect(matchBlockedCommand("hello", cfg)).toBeNull();
    expect(matchBlockedCommand("what is status", cfg)).toBeNull();
    expect(matchBlockedCommand("", cfg)).toBeNull();
  });

  it("matches case-insensitively", () => {
    expect(matchBlockedCommand("/STATUS", cfg)).toBe("/status");
    expect(matchBlockedCommand("/START", cfg)).toBeNull();
  });

  it("intercepts /help when guestHelp is configured (even if in allowed)", () => {
    const cfgWithHelp = makeAllowlist({ allowed: ["/start", "/help"] });
    expect(matchBlockedCommand("/help", cfgWithHelp)).toBe("/help");
  });

  it("does NOT intercept /help when guestHelp is null", () => {
    const cfgNoHelp = makeAllowlist({ guestHelp: null, allowed: ["/start", "/help"] });
    // /help is in allowed list and guestHelp is null → allow it
    expect(matchBlockedCommand("/help", cfgNoHelp)).toBeNull();
  });

  it("blocks /help when guestHelp is null AND /help is NOT in allowed", () => {
    const cfgNoHelp = makeAllowlist({ guestHelp: null });
    // /help is NOT in allowed list → blocked by allowlist
    expect(matchBlockedCommand("/help", cfgNoHelp)).toBe("/help");
  });

  it("handles leading whitespace", () => {
    expect(matchBlockedCommand("  /debug", cfg)).toBe("/debug");
    expect(matchBlockedCommand("  /start", cfg)).toBeNull();
  });

  it("blocks any future unknown /commands automatically", () => {
    // This is the key benefit of allowlist mode — new commands are blocked by default
    expect(matchBlockedCommand("/newfeature2027", cfg)).toBe("/newfeature2027");
    expect(matchBlockedCommand("/somethingelse", cfg)).toBe("/somethingelse");
  });
});

// ---------------------------------------------------------------------------
// setPendingBlock / consumePendingBlock
// ---------------------------------------------------------------------------

describe("setPendingBlock / consumePendingBlock", () => {
  beforeEach(() => {
    consumePendingBlock();
  });

  it("returns null when no block is pending", () => {
    expect(consumePendingBlock()).toBeNull();
  });

  it("returns command after setPendingBlock", () => {
    setPendingBlock("/status");
    expect(consumePendingBlock()).toBe("/status");
  });

  it("clears after consumption (single use)", () => {
    setPendingBlock("/status");
    consumePendingBlock();
    expect(consumePendingBlock()).toBeNull();
  });

  it("latest setPendingBlock wins", () => {
    setPendingBlock("/status");
    setPendingBlock("/help");
    expect(consumePendingBlock()).toBe("/help");
  });
});

// ---------------------------------------------------------------------------
// getBlockResponse
// ---------------------------------------------------------------------------

describe("getBlockResponse", () => {
  it("returns guestHelp for /help command", () => {
    const cfg = makeBlocklist({ guestHelp: "Custom help" });
    expect(getBlockResponse("/help", cfg)).toBe("Custom help");
  });

  it("returns blockResponse for /help when guestHelp is null", () => {
    const cfg = makeBlocklist({ guestHelp: null });
    expect(getBlockResponse("/help", cfg)).toBe("I'm a bot. /help for commands");
  });

  it("returns blockResponse for other commands", () => {
    const cfg = makeBlocklist();
    expect(getBlockResponse("/status", cfg)).toBe("I'm a bot. /help for commands");
    expect(getBlockResponse("/whoami", cfg)).toBe("I'm a bot. /help for commands");
  });

  it("works with allowlist config too", () => {
    const cfg = makeAllowlist({ guestHelp: "Allowlist help" });
    expect(getBlockResponse("/help", cfg)).toBe("Allowlist help");
    expect(getBlockResponse("/config", cfg)).toBe("I'm a bot. /help for commands");
  });
});

// ---------------------------------------------------------------------------
// isAdminByTools
// ---------------------------------------------------------------------------

describe("isAdminByTools", () => {
  const roles = {
    admin: { tools: "*" as const },
    operator: { tools: ["catalog_search"] },
    guest: { tools: ["help"] },
  };

  it("returns true for role with tools: '*'", () => {
    expect(isAdminByTools("admin", roles)).toBe(true);
  });

  it("returns false for role with specific tools", () => {
    expect(isAdminByTools("operator", roles)).toBe(false);
    expect(isAdminByTools("guest", roles)).toBe(false);
  });

  it("returns false for unknown role", () => {
    expect(isAdminByTools("nonexistent", roles)).toBe(false);
  });
});
