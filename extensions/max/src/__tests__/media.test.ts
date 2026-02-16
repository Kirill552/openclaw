import { describe, it, expect } from "vitest";
import { detectMediaType } from "../media.js";

describe("detectMediaType", () => {
  it("should detect image types", () => {
    expect(detectMediaType("photo.jpg")).toBe("image");
    expect(detectMediaType("photo.png")).toBe("image");
    expect(detectMediaType("photo.gif")).toBe("image");
    expect(detectMediaType("photo.webp")).toBe("image");
  });

  it("should detect video types", () => {
    expect(detectMediaType("clip.mp4")).toBe("video");
    expect(detectMediaType("clip.mov")).toBe("video");
    expect(detectMediaType("clip.avi")).toBe("video");
    expect(detectMediaType("clip.webm")).toBe("video");
  });

  it("should detect audio types", () => {
    expect(detectMediaType("song.mp3")).toBe("audio");
    expect(detectMediaType("song.ogg")).toBe("audio");
    expect(detectMediaType("song.wav")).toBe("audio");
    expect(detectMediaType("voice.opus")).toBe("audio");
  });

  it("should default to file for unknown extensions", () => {
    expect(detectMediaType("doc.pdf")).toBe("file");
    expect(detectMediaType("data.zip")).toBe("file");
    expect(detectMediaType("noext")).toBe("file");
  });

  it("should handle URLs with query params", () => {
    expect(detectMediaType("https://example.com/photo.jpg?w=100")).toBe("image");
    expect(detectMediaType("https://example.com/video.mp4#t=10")).toBe("video");
  });

  it("should handle MIME type hint", () => {
    expect(detectMediaType("file", "image/jpeg")).toBe("image");
    expect(detectMediaType("file", "video/mp4")).toBe("video");
    expect(detectMediaType("file", "audio/mpeg")).toBe("audio");
    expect(detectMediaType("file", "application/pdf")).toBe("file");
  });
});
