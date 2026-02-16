import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RateLimiter } from "../rate-limiter.js";

describe("RateLimiter", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("allows logging when under limit", () => {
    const limiter = new RateLimiter(3);
    expect(limiter.shouldLog("peer-1")).toBe(true);
    expect(limiter.shouldLog("peer-1")).toBe(true);
    expect(limiter.shouldLog("peer-1")).toBe(true);
  });

  it("suppresses logging when limit exceeded", () => {
    const limiter = new RateLimiter(2);
    expect(limiter.shouldLog("peer-1")).toBe(true);  // 1st — allowed
    expect(limiter.shouldLog("peer-1")).toBe(true);  // 2nd — allowed
    expect(limiter.shouldLog("peer-1")).toBe(false); // 3rd — suppressed
    expect(limiter.shouldLog("peer-1")).toBe(false); // 4th — suppressed
  });

  it("tracks peers independently", () => {
    const limiter = new RateLimiter(1);
    expect(limiter.shouldLog("peer-a")).toBe(true);  // peer-a: 1st — allowed
    expect(limiter.shouldLog("peer-b")).toBe(true);  // peer-b: 1st — allowed
    expect(limiter.shouldLog("peer-a")).toBe(false); // peer-a: 2nd — suppressed
    expect(limiter.shouldLog("peer-b")).toBe(false); // peer-b: 2nd — suppressed
  });

  it("resets after 60 seconds", () => {
    const limiter = new RateLimiter(1);
    expect(limiter.shouldLog("peer-1")).toBe(true);  // allowed
    expect(limiter.shouldLog("peer-1")).toBe(false); // suppressed

    vi.advanceTimersByTime(60_000);

    // Window reset — should allow again
    expect(limiter.shouldLog("peer-1")).toBe(true);
    expect(limiter.shouldLog("peer-1")).toBe(false); // suppressed again in new window
  });

  it("returns suppressed count via getSuppressed", () => {
    const limiter = new RateLimiter(2);
    expect(limiter.getSuppressed("peer-1")).toBe(0);

    limiter.shouldLog("peer-1"); // 1st — allowed
    limiter.shouldLog("peer-1"); // 2nd — allowed
    expect(limiter.getSuppressed("peer-1")).toBe(0);

    limiter.shouldLog("peer-1"); // 3rd — suppressed
    expect(limiter.getSuppressed("peer-1")).toBe(1);

    limiter.shouldLog("peer-1"); // 4th — suppressed
    expect(limiter.getSuppressed("peer-1")).toBe(2);

    // Other peer should have 0 suppressed
    expect(limiter.getSuppressed("peer-2")).toBe(0);
  });
});
