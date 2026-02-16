import { describe, it, expect } from "vitest";
import { rbacConfigSchema } from "../config.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal valid v2 config — all required fields, no optional ones. */
function minimalConfig() {
  return {
    roles: {
      admin: { users: ["408001372"], tools: "*" },
      guest: { users: "*", tools: ["memory_search"] },
    },
    defaultRole: "guest",
  };
}

/** Full v2 config — every field present. */
function fullConfig() {
  return {
    roles: {
      admin: {
        users: ["408001372", "447903128"],
        tools: "*",
        channels: "*",
      },
      operator: {
        users: ["factory_user_17"],
        tools: ["@read_tools", "catalog_search"],
        channels: ["telegram"],
      },
      guest: {
        users: "*",
        tools: ["memory_search"],
        channels: ["max"],
      },
    },
    defaultRole: "guest",
    logBlocked: true,
    logAllowed: true,
    failSafe: "deny",
    toolGroups: {
      read_tools: ["memory_search", "get_recent_news"],
      write_tools: ["send_message", "run_broadcast"],
    },
    rateLimit: {
      maxBlockedPerMinute: 30,
      action: "suppress-logs",
    },
  };
}

// ---------------------------------------------------------------------------
// Parsing new fields
// ---------------------------------------------------------------------------

describe("rbacConfigSchema.parse — new v2 fields", () => {
  it("parses channels as string[] on a role", () => {
    const raw = minimalConfig();
    (raw.roles.admin as Record<string, unknown>).channels = ["telegram", "max"];
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.roles.admin.channels).toEqual(["telegram", "max"]);
  });

  it("parses channels as wildcard '*'", () => {
    const raw = minimalConfig();
    (raw.roles.admin as Record<string, unknown>).channels = "*";
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.roles.admin.channels).toBe("*");
  });

  it("parses toolGroups", () => {
    const cfg = rbacConfigSchema.parse(fullConfig());
    expect(cfg.toolGroups).toEqual({
      read_tools: ["memory_search", "get_recent_news"],
      write_tools: ["send_message", "run_broadcast"],
    });
  });

  it("parses logAllowed", () => {
    const cfg = rbacConfigSchema.parse(fullConfig());
    expect(cfg.logAllowed).toBe(true);
  });

  it("parses failSafe as 'deny'", () => {
    const cfg = rbacConfigSchema.parse(fullConfig());
    expect(cfg.failSafe).toBe("deny");
  });

  it("parses failSafe as 'allow'", () => {
    const raw = fullConfig();
    raw.failSafe = "allow";
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.failSafe).toBe("allow");
  });

  it("parses rateLimit", () => {
    const cfg = rbacConfigSchema.parse(fullConfig());
    expect(cfg.rateLimit).toEqual({ maxBlockedPerMinute: 30, action: "suppress-logs" });
  });

  it("returns warnings array (empty for valid config)", () => {
    const cfg = rbacConfigSchema.parse(fullConfig());
    expect(cfg.warnings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Default values when fields omitted
// ---------------------------------------------------------------------------

describe("rbacConfigSchema.parse — defaults", () => {
  it("defaults channels to '*' when omitted from role", () => {
    const cfg = rbacConfigSchema.parse(minimalConfig());
    expect(cfg.roles.admin.channels).toBe("*");
    expect(cfg.roles.guest.channels).toBe("*");
  });

  it("defaults toolGroups to {} when omitted", () => {
    const cfg = rbacConfigSchema.parse(minimalConfig());
    expect(cfg.toolGroups).toEqual({});
  });

  it("defaults logAllowed to false when omitted", () => {
    const cfg = rbacConfigSchema.parse(minimalConfig());
    expect(cfg.logAllowed).toBe(false);
  });

  it("defaults failSafe to 'deny' when omitted", () => {
    const cfg = rbacConfigSchema.parse(minimalConfig());
    expect(cfg.failSafe).toBe("deny");
  });

  it("defaults rateLimit to null when omitted", () => {
    const cfg = rbacConfigSchema.parse(minimalConfig());
    expect(cfg.rateLimit).toBeNull();
  });

  it("defaults logBlocked to true when omitted", () => {
    const cfg = rbacConfigSchema.parse(minimalConfig());
    expect(cfg.logBlocked).toBe(true);
  });

  it("defaults defaultRole to 'guest' when omitted", () => {
    const raw = {
      roles: {
        guest: { users: "*", tools: ["help"] },
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.defaultRole).toBe("guest");
  });
});

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

describe("rbacConfigSchema.parse — validation errors", () => {
  it("throws when wildcard users role comes BEFORE specific users role", () => {
    const raw = {
      roles: {
        catchall: { users: "*", tools: ["help"] },
        admin: { users: ["408001372"], tools: "*" },
      },
      defaultRole: "catchall",
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/wildcard.*before/i);
  });

  it("does NOT throw when wildcard users role comes AFTER specific users role", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
        guest: { users: "*", tools: ["help"] },
      },
      defaultRole: "guest",
    };
    expect(() => rbacConfigSchema.parse(raw)).not.toThrow();
  });

  it("throws when defaultRole is missing from roles", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
      },
      defaultRole: "nonexistent",
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/defaultRole.*not found/);
  });

  it("throws when @group reference has no matching toolGroup", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
        guest: { users: "*", tools: ["@missing_group", "help"] },
      },
      defaultRole: "guest",
      toolGroups: {},
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/@missing_group/);
  });

  it("throws when @group reference used and toolGroups is absent", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
        guest: { users: "*", tools: ["@some_group"] },
      },
      defaultRole: "guest",
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/@some_group/);
  });

  it("does NOT throw when @group reference matches a defined toolGroup", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
        guest: { users: "*", tools: ["@read_tools"] },
      },
      defaultRole: "guest",
      toolGroups: {
        read_tools: ["memory_search", "help"],
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).not.toThrow();
  });

  it("throws when failSafe has invalid value", () => {
    const raw = {
      ...minimalConfig(),
      failSafe: "maybe",
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/failSafe/);
  });

  it("throws when channels has invalid value (number)", () => {
    const raw = minimalConfig();
    (raw.roles.admin as Record<string, unknown>).channels = 42;
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/channels/);
  });

  it("throws when channels has invalid value (array of numbers)", () => {
    const raw = minimalConfig();
    (raw.roles.admin as Record<string, unknown>).channels = [1, 2];
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/channels/);
  });

  it("throws when roles is empty", () => {
    const raw = { roles: {}, defaultRole: "guest" };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/at least one role/);
  });

  it("throws when roles is not an object", () => {
    const raw = { roles: "bad", defaultRole: "guest" };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/must be an object/);
  });

  it("throws when config is not an object", () => {
    expect(() => rbacConfigSchema.parse(null)).toThrow(/must be an object/);
    expect(() => rbacConfigSchema.parse("string")).toThrow(/must be an object/);
  });
});

// ---------------------------------------------------------------------------
// Warnings collection
// ---------------------------------------------------------------------------

describe("rbacConfigSchema.parse — warnings", () => {
  it("warns on empty tools array", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
        guest: { users: "*", tools: [] as string[] },
      },
      defaultRole: "guest",
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.warnings.length).toBeGreaterThan(0);
    expect(cfg.warnings.some((w: string) => /empty.*tools/i.test(w))).toBe(true);
  });

  it("warns on empty channels array", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
        guest: { users: "*", tools: ["help"], channels: [] as string[] },
      },
      defaultRole: "guest",
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.warnings.length).toBeGreaterThan(0);
    expect(cfg.warnings.some((w: string) => /empty.*channels/i.test(w))).toBe(true);
  });

  it("returns empty warnings for valid config with no issues", () => {
    const cfg = rbacConfigSchema.parse(fullConfig());
    expect(cfg.warnings).toEqual([]);
  });

  it("collects multiple warnings", () => {
    const raw = {
      roles: {
        admin: { users: ["408001372"], tools: "*" },
        locked: { users: ["123"], tools: [] as string[], channels: [] as string[] },
        guest: { users: "*", tools: [] as string[] },
      },
      defaultRole: "guest",
    };
    const cfg = rbacConfigSchema.parse(raw);
    // locked has empty tools + empty channels, guest has empty tools
    expect(cfg.warnings.length).toBeGreaterThanOrEqual(3);
  });
});

// ---------------------------------------------------------------------------
// systemCommands parsing
// ---------------------------------------------------------------------------

describe("rbacConfigSchema.parse — systemCommands (blocklist)", () => {
  it("defaults systemCommands to null when omitted", () => {
    const cfg = rbacConfigSchema.parse(minimalConfig());
    expect(cfg.systemCommands).toBeNull();
  });

  it("defaults mode to 'blocklist' when omitted", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        blocked: ["/status"],
        blockResponse: "Blocked.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.mode).toBe("blocklist");
  });

  it("parses valid blocklist config", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        blocked: ["/status", "/whoami", "/context"],
        guestHelp: "I'm a bot. Try /news or /help.",
        blockResponse: "Command not available.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.mode).toBe("blocklist");
    expect(cfg.systemCommands!.blocked).toEqual(["/status", "/whoami", "/context"]);
    expect(cfg.systemCommands!.allowed).toEqual([]);
    expect(cfg.systemCommands!.guestHelp).toBe("I'm a bot. Try /news or /help.");
    expect(cfg.systemCommands!.blockResponse).toBe("Command not available.");
  });

  it("normalizes blocked commands to lowercase with leading /", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        blocked: ["Status", "/WHOAMI", "context"],
        blockResponse: "Blocked.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.blocked).toEqual(["/status", "/whoami", "/context"]);
  });

  it("defaults guestHelp to null when omitted", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        blocked: ["/status"],
        blockResponse: "Blocked.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.guestHelp).toBeNull();
  });

  it("throws when blocklist mode has empty blocked array", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "blocklist",
        blocked: [],
        blockResponse: "Blocked.",
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/blocked.*non-empty.*blocklist/i);
  });

  it("throws when blocklist mode has no blocked field", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "blocklist",
        blockResponse: "Blocked.",
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/blocked.*non-empty.*blocklist/i);
  });
});

describe("rbacConfigSchema.parse — systemCommands (allowlist)", () => {
  it("parses valid allowlist config", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "allowlist",
        allowed: ["/start", "/stop", "/news"],
        guestHelp: "Bot help",
        blockResponse: "Not available.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.mode).toBe("allowlist");
    expect(cfg.systemCommands!.allowed).toEqual(["/start", "/stop", "/news"]);
    expect(cfg.systemCommands!.blocked).toEqual([]);
    expect(cfg.systemCommands!.guestHelp).toBe("Bot help");
  });

  it("normalizes allowed commands to lowercase with leading /", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "allowlist",
        allowed: ["Start", "/STOP", "news"],
        blockResponse: "Blocked.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.allowed).toEqual(["/start", "/stop", "/news"]);
  });

  it("accepts empty allowed array (blocks ALL /commands)", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "allowlist",
        allowed: [],
        blockResponse: "No commands available.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.allowed).toEqual([]);
  });

  it("throws when allowlist mode has no allowed field", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "allowlist",
        blockResponse: "Blocked.",
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/allowed.*required.*allowlist/i);
  });

  it("throws when allowed is not an array", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "allowlist",
        allowed: "/start",
        blockResponse: "Blocked.",
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/allowed.*string\[\]/i);
  });
});

describe("rbacConfigSchema.parse — systemCommands (validation)", () => {
  it("throws when blockResponse is missing", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        blocked: ["/status"],
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/blockResponse.*string/i);
  });

  it("throws when guestHelp is not a string or null", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        blocked: ["/status"],
        guestHelp: 42,
        blockResponse: "Blocked.",
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/guestHelp.*string/i);
  });

  it("throws when systemCommands is not an object", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: "bad",
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/must be an object/);
  });

  it("throws when mode is invalid", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        mode: "something",
        blocked: ["/status"],
        blockResponse: "Blocked.",
      },
    };
    expect(() => rbacConfigSchema.parse(raw)).toThrow(/mode.*blocklist.*allowlist/i);
  });

  it("accepts explicit guestHelp: null", () => {
    const raw = {
      ...minimalConfig(),
      systemCommands: {
        blocked: ["/status"],
        guestHelp: null,
        blockResponse: "Blocked.",
      },
    };
    const cfg = rbacConfigSchema.parse(raw);
    expect(cfg.systemCommands!.guestHelp).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Backward compatibility — v1 config still works
// ---------------------------------------------------------------------------

describe("rbacConfigSchema.parse — backward compatibility", () => {
  it("parses a v1-style config without new fields", () => {
    const v1Config = {
      roles: {
        admin: { users: ["408001372", "447903128"], tools: "*" },
        guest: { users: "*", tools: ["memory_search", "get_recent_news"] },
      },
      defaultRole: "guest",
      logBlocked: true,
    };
    const cfg = rbacConfigSchema.parse(v1Config);
    expect(cfg.roles.admin.users).toEqual(["408001372", "447903128"]);
    expect(cfg.roles.admin.tools).toBe("*");
    expect(cfg.roles.admin.channels).toBe("*");
    expect(cfg.roles.guest.channels).toBe("*");
    expect(cfg.toolGroups).toEqual({});
    expect(cfg.logAllowed).toBe(false);
    expect(cfg.failSafe).toBe("deny");
    expect(cfg.rateLimit).toBeNull();
    expect(cfg.warnings).toEqual([]);
  });
});
