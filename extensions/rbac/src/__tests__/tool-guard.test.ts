import { describe, it, expect } from "vitest";
import { checkToolAccess, expandTools } from "../tool-guard.js";
import type { RBACConfig } from "../config.js";

/** Helper that fills all required RBACConfig fields with sane defaults. */
function makeConfig(partial: Partial<RBACConfig> & Pick<RBACConfig, "roles">): RBACConfig {
  return {
    defaultRole: "guest",
    logBlocked: true,
    logAllowed: false,
    failSafe: "deny",
    toolGroups: {},
    rateLimit: null,
    warnings: [],
    ...partial,
  };
}

// ---------------------------------------------------------------------------
// Group 1 — v1 behavior (exact match, wildcard "*" tools, unknown role)
// ---------------------------------------------------------------------------
describe("checkToolAccess — v1 behavior", () => {
  const config = makeConfig({
    roles: {
      admin: {
        users: ["408001372"],
        tools: "*",
        channels: "*",
      },
      operator: {
        users: ["factory_user_17"],
        tools: ["catalog_search", "drilling_lookup", "generate_dxf"],
        channels: "*",
      },
      guest: {
        users: "*",
        tools: ["catalog_search", "memory_search"],
        channels: "*",
      },
    },
  });

  it("allows admin to use any tool (wildcard '*')", () => {
    const result = checkToolAccess("exec", "admin", config);
    expect(result.allowed).toBe(true);
    expect(result.role).toBe("admin");
  });

  it("allows operator to use whitelisted tool", () => {
    const result = checkToolAccess("catalog_search", "operator", config);
    expect(result.allowed).toBe(true);
  });

  it("blocks operator from non-whitelisted tool", () => {
    const result = checkToolAccess("exec", "operator", config);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("operator");
    expect(result.reason).toContain("exec");
  });

  it("allows guest to use permitted tool", () => {
    const result = checkToolAccess("memory_search", "guest", config);
    expect(result.allowed).toBe(true);
  });

  it("blocks guest from restricted tool", () => {
    const result = checkToolAccess("exec", "guest", config);
    expect(result.allowed).toBe(false);
  });

  it("blocks unknown role", () => {
    const result = checkToolAccess("anything", "nonexistent", config);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Unknown role");
  });
});

// ---------------------------------------------------------------------------
// Group 2 — wildcards (tool entries ending with _*)
// ---------------------------------------------------------------------------
describe("checkToolAccess — wildcards", () => {
  const config = makeConfig({
    roles: {
      operator: {
        users: ["op1"],
        tools: ["catalog_search", "exec_*"],
        channels: "*",
      },
      guest: {
        users: "*",
        tools: ["memory_search"],
        channels: "*",
      },
    },
  });

  it("matches tool by wildcard prefix", () => {
    const result = checkToolAccess("exec_shell", "operator", config);
    expect(result.allowed).toBe(true);
  });

  it("still matches exact tool alongside wildcards", () => {
    const result = checkToolAccess("catalog_search", "operator", config);
    expect(result.allowed).toBe(true);
  });

  it("blocks unrelated tool even when wildcards exist", () => {
    const result = checkToolAccess("browser_open", "operator", config);
    expect(result.allowed).toBe(false);
  });

  it("does NOT match the prefix itself (requires at least one trailing char)", () => {
    // "exec_*" should NOT match "exec" — must have the underscore + at least one char
    const result = checkToolAccess("exec", "operator", config);
    expect(result.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Group 3 — @group references
// ---------------------------------------------------------------------------
describe("checkToolAccess — @groups", () => {
  const config = makeConfig({
    roles: {
      reader: {
        users: ["u1"],
        tools: ["@news_read"],
        channels: "*",
      },
      editor: {
        users: ["u2"],
        tools: ["@news_read", "send_message"],
        channels: "*",
      },
      power: {
        users: ["u3"],
        tools: ["@news_read", "exec_*"],
        channels: "*",
      },
      guest: {
        users: "*",
        tools: ["memory_search"],
        channels: "*",
      },
    },
    toolGroups: {
      news_read: ["get_recent_news", "get_bot_status", "get_stats"],
    },
  });

  it("allows tool that belongs to referenced group", () => {
    const result = checkToolAccess("get_recent_news", "reader", config);
    expect(result.allowed).toBe(true);
  });

  it("blocks tool that is NOT in the referenced group", () => {
    const result = checkToolAccess("send_message", "reader", config);
    expect(result.allowed).toBe(false);
  });

  it("allows both group tools and explicit tools to coexist", () => {
    // editor has @news_read + send_message
    const r1 = checkToolAccess("get_bot_status", "editor", config);
    expect(r1.allowed).toBe(true);
    const r2 = checkToolAccess("send_message", "editor", config);
    expect(r2.allowed).toBe(true);
  });

  it("allows group tools and wildcard tools to coexist", () => {
    // power has @news_read + exec_*
    const r1 = checkToolAccess("get_stats", "power", config);
    expect(r1.allowed).toBe(true);
    const r2 = checkToolAccess("exec_shell", "power", config);
    expect(r2.allowed).toBe(true);
    // but unrelated tool blocked
    const r3 = checkToolAccess("browser_open", "power", config);
    expect(r3.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Group 4 — empty tools array
// ---------------------------------------------------------------------------
describe("checkToolAccess — empty tools", () => {
  const config = makeConfig({
    roles: {
      locked: {
        users: ["u1"],
        tools: [],
        channels: "*",
      },
    },
  });

  it("blocks everything when tools array is empty", () => {
    const r1 = checkToolAccess("exec", "locked", config);
    expect(r1.allowed).toBe(false);
    const r2 = checkToolAccess("memory_search", "locked", config);
    expect(r2.allowed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// expandTools unit tests
// ---------------------------------------------------------------------------
describe("expandTools", () => {
  it("separates exact tools from wildcards and expands groups", () => {
    const config = makeConfig({
      roles: {},
      toolGroups: {
        news_read: ["get_recent_news", "get_stats"],
      },
    });
    const result = expandTools(
      ["send_message", "exec_*", "@news_read"],
      config,
    );
    expect(result.exact).toContain("send_message");
    expect(result.exact).toContain("get_recent_news");
    expect(result.exact).toContain("get_stats");
    expect(result.wildcards).toEqual(["exec_*"]);
    // groups should NOT remain as-is in exact
    expect(result.exact).not.toContain("@news_read");
  });

  it("returns empty arrays for empty input", () => {
    const config = makeConfig({ roles: {} });
    const result = expandTools([], config);
    expect(result.exact).toEqual([]);
    expect(result.wildcards).toEqual([]);
  });
});
