import type { ChannelAccountSnapshot, ChannelStatusIssue } from "openclaw/plugin-sdk";

type MaxAccountStatus = {
  accountId?: unknown;
  enabled?: unknown;
  configured?: unknown;
  dmPolicy?: unknown;
  lastError?: unknown;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === "object");

const asString = (value: unknown): string | undefined =>
  typeof value === "string" ? value : typeof value === "number" ? String(value) : undefined;

function readMaxAccountStatus(value: ChannelAccountSnapshot): MaxAccountStatus | null {
  if (!isRecord(value)) {
    return null;
  }
  return {
    accountId: value.accountId,
    enabled: value.enabled,
    configured: value.configured,
    dmPolicy: value.dmPolicy,
    lastError: value.lastError,
  };
}

export function collectMaxStatusIssues(
  accounts: ChannelAccountSnapshot[],
): ChannelStatusIssue[] {
  const issues: ChannelStatusIssue[] = [];
  for (const entry of accounts) {
    const account = readMaxAccountStatus(entry);
    if (!account) {
      continue;
    }
    const accountId = asString(account.accountId) ?? "default";
    const enabled = account.enabled !== false;
    if (!enabled) {
      continue;
    }

    const configured = account.configured === true;
    const lastError = asString(account.lastError)?.trim();

    if (!configured) {
      issues.push({
        channel: "max",
        accountId,
        kind: "auth",
        message: lastError ?? "Missing bot token.",
        fix: "Set MAX_BOT_TOKEN env var or channels.max.botToken in config.",
      });
      continue;
    }

    if (account.dmPolicy === "open") {
      issues.push({
        channel: "max",
        accountId,
        kind: "config",
        message: 'MAX dmPolicy is "open", allowing any user to message the bot.',
        fix: 'Set channels.max.dmPolicy to "pairing" or "allowlist" to restrict access.',
      });
    }
  }
  return issues;
}
