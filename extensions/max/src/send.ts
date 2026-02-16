import { getMaxApi } from "./bot.js";
import { buildMaxInlineKeyboard } from "./keyboard.js";
import { markSent } from "./sent-cache.js";
import type { MaxSendResult } from "./types.js";

async function withRetry<T>(
  fn: () => Promise<T>,
  maxAttempts = 3,
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const status = (err as { status?: number }).status;

      // Don't retry client errors except rate limit
      if (status && status >= 400 && status < 500 && status !== 429) {
        throw err;
      }

      // Rate limit: wait before retry
      if (status === 429) {
        const delay = 1000 * attempt;
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }

      // Server errors: exponential backoff
      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, 500 * Math.pow(2, attempt - 1)));
      }
    }
  }
  throw lastError;
}

export type SendTextOptions = {
  accountId: string;
  chatId: number;
  text: string;
  format?: "markdown" | "html";
  replyToMid?: string;
  silent?: boolean;
  buttons?: Array<Array<{ type: string; text: string; data?: string; url?: string }>>;
};

export type SendMediaOptions = {
  accountId: string;
  chatId: number;
  mediaUrl: string;
  caption?: string;
};

export async function sendTextMax(opts: SendTextOptions): Promise<MaxSendResult> {
  try {
    const api = getMaxApi(opts.accountId);
    
    const extra: Record<string, unknown> = {
      notify: !opts.silent,
    };
    
    if (opts.format) {
      extra.format = opts.format;
    }
    
    if (opts.replyToMid) {
      extra.link = { type: "reply", mid: opts.replyToMid };
    }
    
    if (opts.buttons && opts.buttons.length > 0) {
      extra.attachments = [buildMaxInlineKeyboard(opts.buttons)];
    }

    const result = await withRetry(() =>
      api.sendMessageToChat(opts.chatId, opts.text, extra as Parameters<typeof api.sendMessageToChat>[2])
    );

    const messageId = String((result as Record<string, unknown>).message_id ?? "");
    markSent(messageId);

    return {
      ok: true,
      messageId,
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function sendImageMax(opts: SendMediaOptions): Promise<MaxSendResult> {
  try {
    const api = getMaxApi(opts.accountId);
    
    const uploadResult = await api.uploadImage({ url: opts.mediaUrl });
    
    const imgResult = uploadResult as { photos?: Record<string, { token: string }> };
    let token: string | undefined;
    if (imgResult.photos) {
      const photos = Object.values(imgResult.photos);
      if (photos.length > 0 && photos[0].token) {
        token = photos[0].token;
      }
    }
    
    if (!token) {
      return { ok: false, error: "Failed to upload image" };
    }

    const result = await api.sendMessageToChat(opts.chatId, opts.caption ?? "", {
      attachments: [{ type: "image", payload: { token } }],
    } as Parameters<typeof api.sendMessageToChat>[2]);

    return {
      ok: true,
      messageId: String((result as Record<string, unknown>).message_id ?? ""),
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function editMessageMax(opts: {
  accountId: string;
  messageId: string;
  text: string;
  format?: "markdown" | "html";
}): Promise<MaxSendResult> {
  try {
    const api = getMaxApi(opts.accountId);
    
    await withRetry(() =>
      api.editMessage(opts.messageId, {
        text: opts.text,
        format: opts.format,
      } as Parameters<typeof api.editMessage>[1])
    );

    return { ok: true, messageId: opts.messageId };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function deleteMessageMax(opts: {
  accountId: string;
  messageId: string;
}): Promise<MaxSendResult> {
  try {
    const api = getMaxApi(opts.accountId);
    await withRetry(() => api.deleteMessage(opts.messageId));
    return { ok: true, messageId: opts.messageId };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function answerCallbackMax(opts: {
  accountId: string;
  callbackId: string;
  text?: string;
  showAlert?: boolean;
  message?: { text: string; format?: "markdown" | "html" };
}): Promise<MaxSendResult> {
  try {
    const api = getMaxApi(opts.accountId);
    const body: Record<string, unknown> = {};

    if (opts.text) {
      body.notification = opts.text;
    }
    if (opts.message) {
      body.message = {
        text: opts.message.text,
        ...(opts.message.format ? { format: opts.message.format } : {}),
      };
    }

    await api.answerOnCallback(
      opts.callbackId,
      body as Parameters<typeof api.answerOnCallback>[1],
    );
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
