import { Bot } from "@maxhub/max-bot-api";
import type { OpenClawConfig } from "openclaw/plugin-sdk";
import type { ResolvedMaxAccount } from "./types.js";
import { registerMaxHandlers, setInboundHandler } from "./bot-handlers.js";

export type MonitorMaxOpts = {
  account: ResolvedMaxAccount;
  config: OpenClawConfig;
  abortSignal?: AbortSignal;
  setStatus: (patch: Record<string, unknown>) => void;
};

export async function monitorMaxProvider(opts: MonitorMaxOpts): Promise<void> {
  const { account, abortSignal, setStatus } = opts;
  
  const log = (msg: string) => {
    console.log(`[openclaw:max:${account.accountId}] ${msg}`);
  };
  
  log(`Starting MAX bot`);
  
  const bot = new Bot(account.token);
  
  registerMaxHandlers(bot, {
    token: account.token,
    accountId: account.accountId,
    format: account.config.format ?? "markdown",
    config: account.config,
  }, log);

  setInboundHandler(async (msgCtx, _accId) => {
    setStatus({
      lastInboundAt: Date.now(),
    });
    log(`Received message from ${msgCtx.userId} in chat ${msgCtx.chatId}`);
  });

  setStatus({
    running: true,
    lastStartAt: Date.now(),
  });

  const stopBot = async () => {
    await bot.stop();
    setStatus({
      running: false,
      lastStopAt: Date.now(),
    });
  };

  abortSignal?.addEventListener("abort", stopBot);

  try {
    await bot.start();
  } catch (err) {
    setStatus({
      running: false,
      lastError: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
}
