import type { OpenClawConfig } from "openclaw/plugin-sdk";
import { DEFAULT_ACCOUNT_ID, normalizeAccountId } from "openclaw/plugin-sdk";
import type { ResolvedMaxAccount, MaxAccountConfig, MaxConfig } from "./types.js";

function listConfiguredAccountIds(cfg: OpenClawConfig): string[] {
  const accounts = (cfg.channels?.max as MaxConfig | undefined)?.accounts;
  if (!accounts || typeof accounts !== "object") {
    return [];
  }
  return Object.keys(accounts).filter(Boolean);
}

export function listMaxAccountIds(cfg: OpenClawConfig): string[] {
  const ids = listConfiguredAccountIds(cfg);
  if (ids.length === 0) {
    return [DEFAULT_ACCOUNT_ID];
  }
  return ids.toSorted((a, b) => a.localeCompare(b));
}

export function resolveDefaultMaxAccountId(cfg: OpenClawConfig): string {
  const maxConfig = cfg.channels?.max as MaxConfig | undefined;
  if (maxConfig?.defaultAccount?.trim()) {
    return maxConfig.defaultAccount.trim();
  }
  const ids = listMaxAccountIds(cfg);
  if (ids.includes(DEFAULT_ACCOUNT_ID)) {
    return DEFAULT_ACCOUNT_ID;
  }
  return ids[0] ?? DEFAULT_ACCOUNT_ID;
}

function resolveAccountConfig(
  cfg: OpenClawConfig,
  accountId: string,
): MaxAccountConfig | undefined {
  const accounts = (cfg.channels?.max as MaxConfig | undefined)?.accounts;
  if (!accounts || typeof accounts !== "object") {
    return undefined;
  }
  return accounts[accountId] as MaxAccountConfig | undefined;
}

function mergeMaxAccountConfig(cfg: OpenClawConfig, accountId: string): MaxAccountConfig {
  const raw = (cfg.channels?.max ?? {}) as MaxConfig;
  const { accounts: _ignored, defaultAccount: _ignored2, ...base } = raw;
  const account = resolveAccountConfig(cfg, accountId) ?? {};
  return { ...base, ...account };
}

function resolveMaxToken(config: MaxAccountConfig, _accountId: string): string {
  if (config.botToken?.trim()) {
    return config.botToken.trim();
  }
  const envToken = process.env.MAX_BOT_TOKEN?.trim();
  if (envToken) {
    return envToken;
  }
  return "";
}

export function resolveMaxAccountSync(params: {
  cfg: OpenClawConfig;
  accountId?: string | null;
}): ResolvedMaxAccount {
  const accountId = normalizeAccountId(params.accountId);
  const baseEnabled =
    (params.cfg.channels?.max as MaxConfig | undefined)?.enabled !== false;
  const merged = mergeMaxAccountConfig(params.cfg, accountId);
  const accountEnabled = merged.enabled !== false;
  const enabled = baseEnabled && accountEnabled;
  const token = resolveMaxToken(merged, accountId);

  return {
    accountId,
    name: merged.name?.trim() || undefined,
    enabled,
    token,
    config: merged,
  };
}

export function resolveMaxAccount(params: {
  cfg: OpenClawConfig;
  accountId?: string | null;
}): ResolvedMaxAccount {
  return resolveMaxAccountSync(params);
}

export function listEnabledMaxAccounts(cfg: OpenClawConfig): ResolvedMaxAccount[] {
  const ids = listMaxAccountIds(cfg);
  return ids
    .map((accountId) => resolveMaxAccountSync({ cfg, accountId }))
    .filter((account) => account.enabled && account.token);
}
