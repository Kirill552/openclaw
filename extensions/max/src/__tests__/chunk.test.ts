// src/__tests__/chunk.test.ts
import { describe, it, expect } from "vitest";
import { chunkMaxText } from "../chunk.js";

describe("chunkMaxText", () => {
  it("should return single chunk for short text", () => {
    expect(chunkMaxText("hello", 4000)).toEqual(["hello"]);
  });

  it("should split by paragraph boundaries", () => {
    const text = "A".repeat(3000) + "\n\n" + "B".repeat(3000);
    const chunks = chunkMaxText(text, 4000);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]).toBe("A".repeat(3000));
    expect(chunks[1]).toBe("B".repeat(3000));
  });

  it("should split by newlines when no paragraph break fits", () => {
    const text = "A".repeat(3000) + "\n" + "B".repeat(3000);
    const chunks = chunkMaxText(text, 4000);
    expect(chunks).toHaveLength(2);
  });

  it("should hard-split when no break point exists", () => {
    const text = "A".repeat(8000);
    const chunks = chunkMaxText(text, 4000);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]).toHaveLength(4000);
    expect(chunks[1]).toHaveLength(4000);
  });

  it("should handle empty text", () => {
    expect(chunkMaxText("", 4000)).toEqual([""]);
  });

  it("should use default limit of 4000", () => {
    const text = "A".repeat(4001);
    const chunks = chunkMaxText(text);
    expect(chunks).toHaveLength(2);
  });

  it("should not create empty trailing chunks", () => {
    const text = "A".repeat(4000);
    const chunks = chunkMaxText(text, 4000);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toBe("A".repeat(4000));
  });

  it("should handle text exactly at limit", () => {
    const text = "hello world";
    const chunks = chunkMaxText(text, 11);
    expect(chunks).toEqual(["hello world"]);
  });
});
