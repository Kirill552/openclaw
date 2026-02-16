export function normalizeMaxTarget(raw?: string | null): string | undefined {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return undefined;
  }
  return trimmed.replace(/^(max|maxmessenger):/i, "");
}

export function formatMaxTarget(target: string): string {
  return `max:${target}`;
}

export function parseMaxTarget(raw: string): { chatId: string } | null {
  const normalized = normalizeMaxTarget(raw);
  if (!normalized) {
    return null;
  }
  return { chatId: normalized };
}
