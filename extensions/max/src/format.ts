// src/format.ts
export function resolveMaxFormat(
  explicit?: "markdown" | "html",
  config?: { format?: "markdown" | "html" | "none" },
): "markdown" | "html" | undefined {
  if (explicit) return explicit;
  const cfgFormat = config?.format;
  if (cfgFormat === "none") return undefined;
  if (cfgFormat === "markdown" || cfgFormat === "html") return cfgFormat;
  return "markdown";
}
