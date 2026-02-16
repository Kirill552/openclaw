import { describe, it, expect } from "vitest";
import { resolveRole } from "../role-resolver.js";
import type { RBACConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Helper: build a valid RBACConfig with channel-aware roles
// ---------------------------------------------------------------------------
function makeConfig(
  overrides: Partial<RBACConfig> & { roles: RBACConfig["roles"] },
): RBACConfig {
  return {
    defaultRole: "guest",
    logBlocked: true,
    logAllowed: false,
    failSafe: "deny",
    toolGroups: {},
    rateLimit: null,
    warnings: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Shared configs
// ---------------------------------------------------------------------------

/** Classic config — channels: "*" everywhere (backward compat) */
const classicConfig = makeConfig({
  roles: {
    admin: {
      users: ["408001372", "447903128"],
      tools: "*",
      channels: "*",
    },
    operator: {
      users: ["factory_user_17"],
      tools: ["catalog_search", "drilling_lookup"],
      channels: "*",
    },
    guest: {
      users: "*",
      tools: ["catalog_search", "memory_search"],
      channels: "*",
    },
  },
  defaultRole: "guest",
});

/** Channel-aware config — different guest roles per channel */
const channelConfig = makeConfig({
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
      tools: ["get_recent_news", "subscribe_user"],
      channels: ["max"],
    },
    guest: {
      users: "*",
      tools: ["memory_search"],
      channels: "*",
    },
  },
  defaultRole: "guest",
});

// ===========================================================================
// Group 1 — backward compatibility (channel = null)
// ===========================================================================

describe("resolveRole — backward compat (channel=null)", () => {
  it("matches admin by user ID", () => {
    expect(resolveRole("408001372", null, classicConfig)).toBe("admin");
  });

  it("matches second admin", () => {
    expect(resolveRole("447903128", null, classicConfig)).toBe("admin");
  });

  it("matches operator by user ID", () => {
    expect(resolveRole("factory_user_17", null, classicConfig)).toBe(
      "operator",
    );
  });

  it("matches guest wildcard for unknown user", () => {
    expect(resolveRole("999999999", null, classicConfig)).toBe("guest");
  });

  it("returns defaultRole when no wildcard role exists", () => {
    const noWildcard = makeConfig({
      roles: {
        admin: {
          users: ["408001372"],
          tools: "*",
          channels: "*",
        },
        restricted: {
          users: ["123"],
          tools: ["help"],
          channels: "*",
        },
      },
      defaultRole: "restricted",
    });
    expect(resolveRole("unknown_user", null, noWildcard)).toBe("restricted");
  });

  it("first matching role wins (admin before guest wildcard)", () => {
    // 408001372 matches both admin (explicit) and guest (wildcard)
    // admin comes first -> should return admin
    expect(resolveRole("408001372", null, classicConfig)).toBe("admin");
  });
});

// ===========================================================================
// Group 2 — channel-aware resolution
// ===========================================================================

describe("resolveRole — channel-aware", () => {
  it("admin matches any channel (channels: '*')", () => {
    expect(resolveRole("408001372", "telegram", channelConfig)).toBe("admin");
    expect(resolveRole("408001372", "max", channelConfig)).toBe("admin");
    expect(resolveRole("408001372", "irc", channelConfig)).toBe("admin");
  });

  it("guest-telegram matches when channel is 'telegram'", () => {
    expect(resolveRole("999999999", "telegram", channelConfig)).toBe(
      "guest-telegram",
    );
  });

  it("guest-max matches when channel is 'max'", () => {
    expect(resolveRole("999999999", "max", channelConfig)).toBe("guest-max");
  });

  it("unknown channel falls through to generic guest (channels: '*')", () => {
    expect(resolveRole("999999999", "irc", channelConfig)).toBe("guest");
  });

  it("null channel matches wildcard channels ('*')", () => {
    // admin has channels: "*", so admin by ID still resolves with null channel
    expect(resolveRole("408001372", null, channelConfig)).toBe("admin");
  });

  it("null channel does NOT match channel-specific role", () => {
    // Unknown user, null channel — guest-telegram (channels: ["telegram"])
    // should NOT match. Should fall through to generic guest (channels: "*").
    expect(resolveRole("999999999", null, channelConfig)).toBe("guest");
  });

  it("specific user matched before channel wildcard", () => {
    // A config where a specific user is listed in a channel-specific role
    // and also matched by a later wildcard role — specific should win.
    const cfg = makeConfig({
      roles: {
        "vip-telegram": {
          users: ["111222333"],
          tools: ["premium_search"],
          channels: ["telegram"],
        },
        guest: {
          users: "*",
          tools: ["memory_search"],
          channels: "*",
        },
      },
      defaultRole: "guest",
    });
    expect(resolveRole("111222333", "telegram", cfg)).toBe("vip-telegram");
  });

  it("user with wrong channel falls to next matching role", () => {
    // User "111222333" is vip-telegram but comes from "max" channel.
    // Should NOT match vip-telegram (wrong channel). Falls to guest.
    const cfg = makeConfig({
      roles: {
        "vip-telegram": {
          users: ["111222333"],
          tools: ["premium_search"],
          channels: ["telegram"],
        },
        guest: {
          users: "*",
          tools: ["memory_search"],
          channels: "*",
        },
      },
      defaultRole: "guest",
    });
    expect(resolveRole("111222333", "max", cfg)).toBe("guest");
  });
});
