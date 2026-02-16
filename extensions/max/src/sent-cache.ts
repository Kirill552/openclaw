// src/sent-cache.ts
const cache = new Map<string, number>();
const TTL = 5 * 60 * 1000; // 5 minutes

export function markSent(messageId: string): void {
  if (!messageId) return;
  cache.set(messageId, Date.now());
}

export function wasSentRecently(messageId: string): boolean {
  const ts = cache.get(messageId);
  if (!ts) return false;
  if (Date.now() - ts > TTL) {
    cache.delete(messageId);
    return false;
  }
  return true;
}

export function cleanupSentCache(): void {
  const now = Date.now();
  for (const [id, ts] of cache) {
    if (now - ts > TTL) cache.delete(id);
  }
}

// Run cleanup periodically
const cleanupInterval = setInterval(cleanupSentCache, TTL);
if (typeof cleanupInterval.unref === "function") {
  cleanupInterval.unref();
}
