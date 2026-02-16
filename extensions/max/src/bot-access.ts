// src/bot-access.ts
export function isMaxSenderAllowed(
  userId: string,
  dmPolicy: "open" | "allowlist" | "pairing" | "disabled",
  allowFrom: Array<string | number>,
): boolean | "pending" {
  switch (dmPolicy) {
    case "open":
      return true;
    case "disabled":
      return false;
    case "pairing":
      return "pending";
    case "allowlist": {
      const normalized = allowFrom.map((e) => String(e).trim());
      if (normalized.includes("*")) return true;
      return normalized.includes(userId);
    }
  }
}

export function isMaxGroupAllowed(
  chatId: string,
  groupPolicy: "open" | "allowlist" | "disabled",
  groups: Record<string, { allow?: boolean; enabled?: boolean }>,
): boolean {
  switch (groupPolicy) {
    case "open":
      return true;
    case "disabled":
      return false;
    case "allowlist": {
      const entry = groups[chatId] ?? groups["*"];
      if (!entry) return false;
      if (entry.enabled === false) return false;
      return entry.allow !== false;
    }
  }
}
