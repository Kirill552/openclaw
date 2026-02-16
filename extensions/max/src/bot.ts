import { Bot } from "@maxhub/max-bot-api";
import type { MaxBotOptions, MaxBotInstance } from "./types.js";

const botInstances = new Map<string, MaxBotInstance>();

export function createMaxBot(opts: MaxBotOptions): Bot {
  const bot = new Bot(opts.token);
  return bot;
}

export function getMaxBot(accountId: string): MaxBotInstance | undefined {
  return botInstances.get(accountId);
}

export function setMaxBot(accountId: string, instance: MaxBotInstance): void {
  botInstances.set(accountId, instance);
}

export function deleteMaxBot(accountId: string): void {
  botInstances.delete(accountId);
}

export async function startMaxBot(opts: MaxBotOptions): Promise<MaxBotInstance> {
  const bot = createMaxBot(opts);
  const instance: MaxBotInstance = {
    bot,
    accountId: opts.accountId,
    token: opts.token,
  };
  setMaxBot(opts.accountId, instance);
  
  await bot.start();
  return instance;
}

export async function stopMaxBot(accountId: string): Promise<void> {
  const instance = getMaxBot(accountId);
  if (instance) {
    const bot = instance.bot as Bot;
    await bot.stop();
    deleteMaxBot(accountId);
  }
}

export function getMaxApi(accountId: string) {
  const instance = getMaxBot(accountId);
  if (!instance) {
    throw new Error(`MAX bot not found for account: ${accountId}`);
  }
  const bot = instance.bot as Bot;
  return bot.api;
}

export async function probeMaxBot(token: string): Promise<{ ok: boolean; name?: string; error?: string }> {
  try {
    const bot = new Bot(token);
    const info = await bot.api.getMyInfo();
    return {
      ok: true,
      name: info.name,
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
