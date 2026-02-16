// src/__tests__/bot-access.test.ts
import { describe, it, expect } from "vitest";
import { isMaxSenderAllowed, isMaxGroupAllowed } from "../bot-access.js";

describe("isMaxSenderAllowed", () => {
  it("should allow all senders with open policy", () => {
    expect(isMaxSenderAllowed("123", "open", [])).toBe(true);
  });

  it("should block all senders with disabled policy", () => {
    expect(isMaxSenderAllowed("123", "disabled", [])).toBe(false);
  });

  it("should allow listed senders with allowlist policy", () => {
    expect(isMaxSenderAllowed("123", "allowlist", ["123", "456"])).toBe(true);
  });

  it("should block unlisted senders with allowlist policy", () => {
    expect(isMaxSenderAllowed("789", "allowlist", ["123", "456"])).toBe(false);
  });

  it("should allow all with allowlist and wildcard", () => {
    expect(isMaxSenderAllowed("anyone", "allowlist", ["*"])).toBe(true);
  });

  it("should return pending for pairing policy", () => {
    expect(isMaxSenderAllowed("123", "pairing", [])).toBe("pending");
  });

  it("should handle numeric allow-from entries", () => {
    expect(isMaxSenderAllowed("123", "allowlist", [123])).toBe(true);
  });
});

describe("isMaxGroupAllowed", () => {
  it("should allow all groups with open policy", () => {
    expect(isMaxGroupAllowed("100", "open", {})).toBe(true);
  });

  it("should block all groups with disabled policy", () => {
    expect(isMaxGroupAllowed("100", "disabled", {})).toBe(false);
  });

  it("should allow listed groups with allowlist policy", () => {
    expect(isMaxGroupAllowed("100", "allowlist", { "100": { allow: true } })).toBe(true);
  });

  it("should block unlisted groups with allowlist policy", () => {
    expect(isMaxGroupAllowed("999", "allowlist", { "100": { allow: true } })).toBe(false);
  });

  it("should allow groups with wildcard entry", () => {
    expect(isMaxGroupAllowed("any", "allowlist", { "*": { allow: true } })).toBe(true);
  });

  it("should block explicitly disabled groups", () => {
    expect(isMaxGroupAllowed("100", "allowlist", { "100": { enabled: false } })).toBe(false);
  });
});
