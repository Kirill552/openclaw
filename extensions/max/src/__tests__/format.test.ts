// src/__tests__/format.test.ts
import { describe, it, expect } from "vitest";
import { resolveMaxFormat } from "../format.js";

describe("resolveMaxFormat", () => {
  it("should use explicit format when provided", () => {
    expect(resolveMaxFormat("html", { format: "markdown" })).toBe("html");
  });

  it("should fall back to account config format", () => {
    expect(resolveMaxFormat(undefined, { format: "html" })).toBe("html");
  });

  it("should default to markdown when nothing configured", () => {
    expect(resolveMaxFormat(undefined, {})).toBe("markdown");
  });

  it("should handle 'none' config by returning undefined", () => {
    expect(resolveMaxFormat(undefined, { format: "none" })).toBeUndefined();
  });
});
