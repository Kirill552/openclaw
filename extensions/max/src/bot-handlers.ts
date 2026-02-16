import type { Bot, Context } from "@maxhub/max-bot-api";
import { isMaxSenderAllowed, isMaxGroupAllowed } from "./bot-access.js";
import { extractMaxMediaUrl } from "./media.js";
import type { MaxAccountConfig, MaxBotEvent, MaxBotOptions, MaxMessageContext } from "./types.js";

type InboundHandler = (ctx: MaxMessageContext, accountId: string) => Promise<void> | void;

let inboundHandler: InboundHandler | null = null;

export function setInboundHandler(handler: InboundHandler): void {
  inboundHandler = handler;
}

type BotEventHandler = (event: MaxBotEvent, accountId: string) => Promise<void> | void;

let botEventHandler: BotEventHandler | null = null;

export function setBotEventHandler(handler: BotEventHandler): void {
  botEventHandler = handler;
}

export function registerMaxHandlers(
  bot: Bot,
  opts: MaxBotOptions & { config?: MaxAccountConfig },
  log: (msg: string) => void,
): void {
  bot.on("message_created", async (ctx: Context) => {
    if (!inboundHandler) {
      return;
    }

    const message = ctx.message;
    if (!message) {
      return;
    }

    const body = message.body;
    const user = ctx.user;
    const chatId = ctx.chatId;

    const messageContext: MaxMessageContext = {
      userId: String(user?.user_id ?? ""),
      chatId: String(chatId ?? ""),
      messageId: String(body?.mid ?? ""),
      text: body?.text ?? undefined,
      attachments: parseAttachments(body?.attachments),
      raw: ctx,
    };

    // Access control check
    if (opts.config) {
      const isGroup = messageContext.chatId !== messageContext.userId;
      if (isGroup) {
        const groupPolicy = opts.config.groupPolicy ?? "open";
        const groups = opts.config.groups ?? {};
        if (!isMaxGroupAllowed(messageContext.chatId, groupPolicy, groups)) {
          log(`MAX: blocked message from disallowed group ${messageContext.chatId}`);
          return;
        }
      } else {
        const dmPolicy = opts.config.dmPolicy ?? "open";
        const allowFrom = (opts.config.allowFrom ?? []).map((e) => String(e));
        const allowed = isMaxSenderAllowed(messageContext.userId, dmPolicy, allowFrom);
        if (allowed === false) {
          log(`MAX: blocked message from disallowed user ${messageContext.userId}`);
          return;
        }
        if (allowed === "pending") {
          log(`MAX: pairing pending for user ${messageContext.userId}`);
          return;
        }
      }
    }

    try {
      await inboundHandler(messageContext, opts.accountId);
    } catch (err) {
      log(`MAX inbound handler error: ${String(err)}`);
    }
  });

  bot.on("message_callback", async (ctx: Context) => {
    if (!inboundHandler) {
      return;
    }

    const callback = ctx.callback;
    const user = ctx.user;
    const message = ctx.message;

    const messageContext: MaxMessageContext = {
      userId: String(user?.user_id ?? ""),
      chatId: String(ctx.chatId ?? ""),
      messageId: String(message?.body?.mid ?? ""),
      callback: callback
        ? {
            payload: String(callback.payload ?? ""),
            callbackId: String(callback.callback_id ?? ""),
          }
        : undefined,
      raw: ctx,
    };

    try {
      await inboundHandler(messageContext, opts.accountId);
    } catch (err) {
      log(`MAX callback handler error: ${String(err)}`);
    }
  });

  bot.on("bot_started", async (ctx: Context) => {
    const user = ctx.user;
    const userId = String(user?.user_id ?? "");
    log(`MAX bot started by user ${userId}`);

    if (botEventHandler) {
      try {
        await botEventHandler({
          type: "bot_started",
          userId,
          chatId: userId,
          raw: ctx,
        }, opts.accountId);
      } catch (err) {
        log(`MAX bot_started handler error: ${String(err)}`);
      }
    }
  });

  bot.on("bot_stopped" as any, async (ctx: Context) => {
    const user = ctx.user;
    const userId = String(user?.user_id ?? "");
    log(`MAX bot stopped by user ${userId}`);

    if (botEventHandler) {
      try {
        await botEventHandler({
          type: "bot_stopped",
          userId,
          chatId: userId,
          raw: ctx,
        }, opts.accountId);
      } catch (err) {
        log(`MAX bot_stopped handler error: ${String(err)}`);
      }
    }
  });

  bot.on("bot_added", async (ctx: Context) => {
    log(`MAX bot added to chat ${ctx.chatId}`);
  });

  bot.on("bot_removed", async (ctx: Context) => {
    log(`MAX bot removed from chat ${ctx.chatId}`);
  });

  bot.on("message_edited" as any, async (ctx: Context) => {
    const message = ctx.message;
    const user = ctx.user;
    log(`MAX message edited by ${user?.user_id} in ${ctx.chatId}`);

    if (botEventHandler) {
      try {
        await botEventHandler({
          type: "message_edited",
          userId: String(user?.user_id ?? ""),
          chatId: String(ctx.chatId ?? ""),
          messageId: String(message?.body?.mid ?? ""),
          text: message?.body?.text ?? undefined,
          raw: ctx,
        }, opts.accountId);
      } catch (err) {
        log(`MAX message_edited handler error: ${String(err)}`);
      }
    }
  });

  bot.on("message_removed" as any, async (ctx: Context) => {
    const user = ctx.user;
    log(`MAX message removed in ${ctx.chatId}`);

    if (botEventHandler) {
      try {
        await botEventHandler({
          type: "message_removed",
          userId: String(user?.user_id ?? ""),
          chatId: String(ctx.chatId ?? ""),
          raw: ctx,
        }, opts.accountId);
      } catch (err) {
        log(`MAX message_removed handler error: ${String(err)}`);
      }
    }
  });

  bot.on("user_added" as any, async (ctx: Context) => {
    const user = ctx.user;
    log(`MAX user ${user?.user_id} added to chat ${ctx.chatId}`);

    if (botEventHandler) {
      try {
        await botEventHandler({
          type: "user_added",
          userId: String(user?.user_id ?? ""),
          chatId: String(ctx.chatId ?? ""),
          raw: ctx,
        }, opts.accountId);
      } catch (err) {
        log(`MAX user_added handler error: ${String(err)}`);
      }
    }
  });

  bot.on("user_removed" as any, async (ctx: Context) => {
    const user = ctx.user;
    log(`MAX user ${user?.user_id} removed from chat ${ctx.chatId}`);

    if (botEventHandler) {
      try {
        await botEventHandler({
          type: "user_removed",
          userId: String(user?.user_id ?? ""),
          chatId: String(ctx.chatId ?? ""),
          raw: ctx,
        }, opts.accountId);
      } catch (err) {
        log(`MAX user_removed handler error: ${String(err)}`);
      }
    }
  });

  bot.on("chat_title_changed" as any, async (ctx: Context) => {
    log(`MAX chat title changed in ${ctx.chatId}`);

    if (botEventHandler) {
      try {
        await botEventHandler({
          type: "chat_title_changed",
          userId: "",
          chatId: String(ctx.chatId ?? ""),
          raw: ctx,
        }, opts.accountId);
      } catch (err) {
        log(`MAX chat_title_changed handler error: ${String(err)}`);
      }
    }
  });
}

function parseAttachments(attachments: unknown): MaxMessageContext["attachments"] {
  if (!Array.isArray(attachments)) {
    return undefined;
  }

  return attachments.map((att: Record<string, unknown>) => {
    const typeStr = String(att.type ?? "file");
    let attType: "image" | "video" | "audio" | "file" | "contact" | "location" = "file";
    if (typeStr === "image" || typeStr === "video" || typeStr === "audio" || typeStr === "contact" || typeStr === "location") {
      attType = typeStr;
    }
    return {
      type: attType,
      payload: att.payload ?? att,
      url: extractMaxMediaUrl({ type: typeStr, payload: att.payload ?? att }),
    };
  });
}
