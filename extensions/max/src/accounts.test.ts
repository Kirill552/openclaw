import { describe, it, expect } from "vitest";
import {
  listMaxAccountIds,
  resolveDefaultMaxAccountId,
  resolveMaxAccountSync,
} from "./accounts.js";
import type { OpenClawConfig } from "openclaw/plugin-sdk";

describe("listMaxAccountIds", () => {
  it("should return default account ID when no accounts configured", () => {
    const cfg = {} as OpenClawConfig;
    expect(listMaxAccountIds(cfg)).toEqual(["default"]);
  });

  it("should list configured account IDs", () => {
    const cfg = {
      channels: {
        max: {
          accounts: {
            account1: { botToken: "token1" },
            account2: { botToken: "token2" },
          },
        },
      },
    } as OpenClawConfig;
    expect(listMaxAccountIds(cfg)).toEqual(["account1", "account2"]);
  });
});

describe("resolveDefaultMaxAccountId", () => {
  it("should return default when no defaultAccount set", () => {
    const cfg = {} as OpenClawConfig;
    expect(resolveDefaultMaxAccountId(cfg)).toBe("default");
  });

  it("should return configured defaultAccount", () => {
    const cfg = {
      channels: {
        max: {
          defaultAccount: "production",
        },
      },
    } as OpenClawConfig;
    expect(resolveDefaultMaxAccountId(cfg)).toBe("production");
  });
});

describe("resolveMaxAccountSync", () => {
  it("should resolve account with token from config", () => {
    const cfg = {
      channels: {
        max: {
          botToken: "test-token",
        },
      },
    } as OpenClawConfig;
    
    const account = resolveMaxAccountSync({ cfg, accountId: null });
    expect(account.token).toBe("test-token");
    expect(account.accountId).toBe("default");
    expect(account.enabled).toBe(true);
  });

  it("should resolve account with token from env", () => {
    process.env.MAX_BOT_TOKEN = "env-token";
    const cfg = {} as OpenClawConfig;
    
    const account = resolveMaxAccountSync({ cfg, accountId: null });
    expect(account.token).toBe("env-token");
    
    delete process.env.MAX_BOT_TOKEN;
  });

  it("should handle disabled account", () => {
    const cfg = {
      channels: {
        max: {
          enabled: false,
          botToken: "test-token",
        },
      },
    } as OpenClawConfig;
    
    const account = resolveMaxAccountSync({ cfg, accountId: null });
    expect(account.enabled).toBe(false);
  });
});
