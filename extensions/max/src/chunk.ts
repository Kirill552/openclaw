// src/chunk.ts
const DEFAULT_LIMIT = 4000;

export function chunkMaxText(text: string, limit = DEFAULT_LIMIT): string[] {
  if (text.length <= limit) return [text];

  const chunks: string[] = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= limit) {
      chunks.push(remaining);
      break;
    }

    const slice = remaining.slice(0, limit);
    let splitAt = limit;

    // Try to split at paragraph boundary (double newline)
    const paraBreak = slice.lastIndexOf("\n\n");
    if (paraBreak > limit * 0.3) {
      splitAt = paraBreak;
    } else {
      // Try newline boundary
      const lineBreak = slice.lastIndexOf("\n");
      if (lineBreak > limit * 0.3) {
        splitAt = lineBreak;
      }
      // Otherwise hard split at limit
    }

    chunks.push(remaining.slice(0, splitAt));
    remaining = remaining.slice(splitAt);
    // Strip leading newlines from next chunk
    remaining = remaining.replace(/^\n+/, "");
  }

  return chunks;
}
