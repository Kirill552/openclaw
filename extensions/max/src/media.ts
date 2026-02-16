import { getMaxApi } from "./bot.js";
import type { MaxSendResult } from "./types.js";

const IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg"]);
const VIDEO_EXTS = new Set(["mp4", "mov", "avi", "webm", "mkv", "flv", "wmv"]);
const AUDIO_EXTS = new Set(["mp3", "ogg", "wav", "opus", "flac", "aac", "m4a", "wma"]);

export type MaxMediaType = "image" | "video" | "audio" | "file";

export function detectMediaType(urlOrPath: string, mimeHint?: string): MaxMediaType {
  if (mimeHint) {
    if (mimeHint.startsWith("image/")) return "image";
    if (mimeHint.startsWith("video/")) return "video";
    if (mimeHint.startsWith("audio/")) return "audio";
    return "file";
  }

  // Extract extension from URL or path
  let ext = "";
  try {
    const pathname = new URL(urlOrPath).pathname;
    ext = pathname.split(".").pop()?.toLowerCase() ?? "";
  } catch {
    // Not a valid URL; strip query/fragment then extract extension
    ext = urlOrPath.split(/[?#]/)[0].split(".").pop()?.toLowerCase() ?? "";
  }

  if (IMAGE_EXTS.has(ext)) return "image";
  if (VIDEO_EXTS.has(ext)) return "video";
  if (AUDIO_EXTS.has(ext)) return "audio";
  return "file";
}

/**
 * Download a URL to a Buffer so we can pass it to the MAX upload API
 * (uploadVideo/uploadAudio/uploadFile only accept source, not URL).
 */
async function downloadToBuffer(url: string): Promise<Buffer> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Download failed: ${response.status} ${response.statusText}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

export async function sendMediaMax(opts: {
  accountId: string;
  chatId: number;
  mediaUrl: string;
  caption?: string;
  format?: "markdown" | "html";
  mediaType?: MaxMediaType;
  mimeType?: string;
}): Promise<MaxSendResult> {
  const type = opts.mediaType ?? detectMediaType(opts.mediaUrl, opts.mimeType);

  try {
    const api = getMaxApi(opts.accountId);

    if (type === "image") {
      // Image upload supports URL directly
      const imageAttachment = await api.uploadImage({ url: opts.mediaUrl });

      // The returned ImageAttachment has a toJson() that produces the right format
      const attachmentJson = imageAttachment.toJson();

      const result = await api.sendMessageToChat(opts.chatId, opts.caption ?? "", {
        attachments: [attachmentJson],
        format: opts.format,
      } as Parameters<typeof api.sendMessageToChat>[2]);

      return {
        ok: true,
        messageId: String((result as Record<string, unknown>).message_id ?? ""),
      };
    }

    // For video/audio/file: the SDK only accepts source (Buffer/ReadStream/path),
    // so we download the URL contents first.
    const buffer = await downloadToBuffer(opts.mediaUrl);

    let attachment: { toJson(): unknown };

    if (type === "video") {
      attachment = await api.uploadVideo({ source: buffer });
    } else if (type === "audio") {
      attachment = await api.uploadAudio({ source: buffer });
    } else {
      attachment = await api.uploadFile({ source: buffer });
    }

    const attachmentJson = attachment.toJson();

    const result = await api.sendMessageToChat(opts.chatId, opts.caption ?? "", {
      attachments: [attachmentJson],
      format: opts.format,
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

export function extractMaxMediaUrl(attachment: { type: string; payload: unknown }): string | null {
  const payload = attachment.payload as Record<string, unknown> | null;
  if (!payload) return null;

  if (typeof payload.url === "string") return payload.url;
  if (typeof payload.link === "string") return payload.link;

  // For photos, check nested photo objects
  if (attachment.type === "image" && payload.photos) {
    const photos = payload.photos as Record<string, { url?: string }>;
    const first = Object.values(photos)[0];
    if (first?.url) return first.url;
  }

  return null;
}
