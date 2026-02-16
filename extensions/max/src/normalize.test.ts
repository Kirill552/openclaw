import { describe, it, expect } from "vitest";
import { normalizeMaxTarget, formatMaxTarget, parseMaxTarget } from "./normalize.js";

describe("normalizeMaxTarget", () => {
  it("should normalize max: prefix", () => {
    expect(normalizeMaxTarget("max:123456")).toBe("123456");
  });

  it("should normalize maxmessenger: prefix", () => {
    expect(normalizeMaxTarget("maxmessenger:123456")).toBe("123456");
  });

  it("should handle case-insensitive prefixes", () => {
    expect(normalizeMaxTarget("MAX:123456")).toBe("123456");
    expect(normalizeMaxTarget("MaxMessenger:123456")).toBe("123456");
  });

  it("should return undefined for empty input", () => {
    expect(normalizeMaxTarget("")).toBeUndefined();
    expect(normalizeMaxTarget(null)).toBeUndefined();
    expect(normalizeMaxTarget(undefined)).toBeUndefined();
  });

  it("should trim whitespace", () => {
    expect(normalizeMaxTarget("  123456  ")).toBe("123456");
  });

  it("should pass through numeric IDs without prefix", () => {
    expect(normalizeMaxTarget("123456")).toBe("123456");
  });
});

describe("formatMaxTarget", () => {
  it("should add max: prefix", () => {
    expect(formatMaxTarget("123456")).toBe("max:123456");
  });
});

describe("parseMaxTarget", () => {
  it("should parse valid target", () => {
    expect(parseMaxTarget("max:123456")).toEqual({ chatId: "123456" });
    expect(parseMaxTarget("123456")).toEqual({ chatId: "123456" });
  });

  it("should return null for empty input", () => {
    expect(parseMaxTarget("")).toBeNull();
  });
});
