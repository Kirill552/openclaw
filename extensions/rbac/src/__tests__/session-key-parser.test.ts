import { describe, it, expect } from "vitest";
import { parseSessionKey } from "../session-key-parser.js";

describe("parseSessionKey", () => {
  it("parses per-channel-peer format", () => {
    const result = parseSessionKey("agent:main:telegram:direct:408001372");
    expect(result).toEqual({
      peerId: "408001372",
      channel: "telegram",
      peerKind: "direct",
    });
  });

  it("parses per-account-channel-peer format", () => {
    const result = parseSessionKey("agent:main:telegram:default:direct:408001372");
    expect(result).toEqual({
      peerId: "408001372",
      channel: "telegram",
      peerKind: "direct",
    });
  });

  it("parses per-peer format", () => {
    const result = parseSessionKey("agent:main:direct:408001372");
    expect(result).toEqual({
      peerId: "408001372",
      channel: null,
      peerKind: "direct",
    });
  });

  it("parses group format", () => {
    const result = parseSessionKey("agent:main:telegram:group:-100123456");
    expect(result).toEqual({
      peerId: "-100123456",
      channel: "telegram",
      peerKind: "group",
    });
  });

  it("parses channel format", () => {
    const result = parseSessionKey("agent:main:telegram:channel:-100123456");
    expect(result).toEqual({
      peerId: "-100123456",
      channel: "telegram",
      peerKind: "channel",
    });
  });

  it("returns null for main scope (no peerId)", () => {
    const result = parseSessionKey("agent:main:main");
    expect(result).toBeNull();
  });

  it("returns null for too-short key", () => {
    const result = parseSessionKey("agent:main");
    expect(result).toBeNull();
  });

  it("returns null for empty string", () => {
    const result = parseSessionKey("");
    expect(result).toBeNull();
  });

  it("handles MAX channel", () => {
    const result = parseSessionKey("agent:main:max:direct:user123");
    expect(result).toEqual({
      peerId: "user123",
      channel: "max",
      peerKind: "direct",
    });
  });
});
