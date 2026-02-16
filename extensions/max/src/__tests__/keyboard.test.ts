import { describe, it, expect } from "vitest";
import { buildMaxInlineKeyboard, mapToMaxButton } from "../keyboard.js";

describe("mapToMaxButton", () => {
  it("should map callback button", () => {
    expect(mapToMaxButton({ type: "callback", text: "Click", data: "payload_1" }))
      .toEqual({ type: "callback", text: "Click", payload: "payload_1" });
  });

  it("should map url button to link button", () => {
    expect(mapToMaxButton({ type: "url", text: "Open", url: "https://example.com" }))
      .toEqual({ type: "link", text: "Open", url: "https://example.com" });
  });

  it("should map contact request button", () => {
    expect(mapToMaxButton({ type: "contact", text: "Share Contact" }))
      .toEqual({ type: "request_contact", text: "Share Contact" });
  });

  it("should map location request button", () => {
    expect(mapToMaxButton({ type: "location", text: "Share Location" }))
      .toEqual({ type: "request_geo_location", text: "Share Location" });
  });

  it("should return null for unknown button type", () => {
    expect(mapToMaxButton({ type: "unknown" as any, text: "X" })).toBeNull();
  });
});

describe("buildMaxInlineKeyboard", () => {
  it("should build keyboard with single row", () => {
    const result = buildMaxInlineKeyboard([
      [{ type: "callback", text: "A", data: "a" }],
    ]);
    expect(result).toEqual({
      type: "inline_keyboard",
      payload: {
        buttons: [[{ type: "callback", text: "A", payload: "a" }]],
      },
    });
  });

  it("should build keyboard with multiple rows", () => {
    const result = buildMaxInlineKeyboard([
      [{ type: "callback", text: "A", data: "a" }, { type: "url", text: "B", url: "https://b.com" }],
      [{ type: "contact", text: "C" }],
    ]);
    expect(result.payload.buttons).toHaveLength(2);
    expect(result.payload.buttons[0]).toHaveLength(2);
    expect(result.payload.buttons[1]).toHaveLength(1);
  });

  it("should filter out null buttons from unknown types", () => {
    const result = buildMaxInlineKeyboard([
      [{ type: "callback", text: "A", data: "a" }, { type: "unknown" as any, text: "X" }],
    ]);
    expect(result.payload.buttons[0]).toHaveLength(1);
  });

  it("should handle empty input", () => {
    const result = buildMaxInlineKeyboard([]);
    expect(result.payload.buttons).toEqual([]);
  });
});
