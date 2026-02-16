import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the bot module
vi.mock("../bot.js", () => ({
  getMaxApi: vi.fn(),
}));

// Mock the sent-cache module
vi.mock("../sent-cache.js", () => ({
  markSent: vi.fn(),
}));

import {
  sendTextMax,
  editMessageMax,
  deleteMessageMax,
  answerCallbackMax,
} from "../send.js";
import { getMaxApi } from "../bot.js";
import { markSent } from "../sent-cache.js";

describe("sendTextMax", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should send text with format", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "123" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "hello",
      format: "markdown",
    });

    expect(result.ok).toBe(true);
    expect(result.messageId).toBe("123");
    expect(mockApi.sendMessageToChat).toHaveBeenCalledWith(
      100,
      "hello",
      expect.objectContaining({ format: "markdown", notify: true }),
    );
  });

  it("should call markSent with the returned message id", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "abc" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 1,
      text: "hi",
    });

    expect(markSent).toHaveBeenCalledWith("abc");
  });

  it("should include reply link when replyToMid is set", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "124" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "reply",
      replyToMid: "original_msg_id",
    });

    expect(mockApi.sendMessageToChat).toHaveBeenCalledWith(
      100,
      "reply",
      expect.objectContaining({
        link: { type: "reply", mid: "original_msg_id" },
      }),
    );
  });

  it("should include inline keyboard when buttons provided", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "125" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "choose",
      buttons: [[{ type: "callback", text: "A", data: "a" }]],
    });

    expect(mockApi.sendMessageToChat).toHaveBeenCalledWith(
      100,
      "choose",
      expect.objectContaining({
        attachments: [
          expect.objectContaining({
            type: "inline_keyboard",
          }),
        ],
      }),
    );
  });

  it("should handle silent mode", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "126" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "quiet",
      silent: true,
    });

    expect(mockApi.sendMessageToChat).toHaveBeenCalledWith(
      100,
      "quiet",
      expect.objectContaining({ notify: false }),
    );
  });

  it("should default notify to true when silent is not set", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "127" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "loud",
    });

    expect(mockApi.sendMessageToChat).toHaveBeenCalledWith(
      100,
      "loud",
      expect.objectContaining({ notify: true }),
    );
  });

  it("should return error on API failure", async () => {
    // Use a 400 status so withRetry does not retry (avoids delay in tests)
    const err = Object.assign(new Error("Network error"), { status: 400 });
    const mockApi = {
      sendMessageToChat: vi.fn().mockRejectedValue(err),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "fail",
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("Network error");
  });

  it("should not include format when format is not set", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "128" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "plain",
    });

    const calledOpts = mockApi.sendMessageToChat.mock.calls[0][2];
    expect(calledOpts).not.toHaveProperty("format");
  });

  it("should not include link when replyToMid is not set", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "129" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "no reply",
    });

    const calledOpts = mockApi.sendMessageToChat.mock.calls[0][2];
    expect(calledOpts).not.toHaveProperty("link");
  });

  it("should not include attachments when buttons are not provided", async () => {
    const mockApi = {
      sendMessageToChat: vi.fn().mockResolvedValue({ message_id: "130" }),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await sendTextMax({
      accountId: "test",
      chatId: 100,
      text: "no buttons",
    });

    const calledOpts = mockApi.sendMessageToChat.mock.calls[0][2];
    expect(calledOpts).not.toHaveProperty("attachments");
  });
});

describe("editMessageMax", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should edit message with format", async () => {
    const mockApi = {
      editMessage: vi.fn().mockResolvedValue({}),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await editMessageMax({
      accountId: "test",
      messageId: "msg_1",
      text: "updated",
      format: "html",
    });

    expect(result.ok).toBe(true);
    expect(result.messageId).toBe("msg_1");
    expect(mockApi.editMessage).toHaveBeenCalledWith(
      "msg_1",
      expect.objectContaining({ text: "updated", format: "html" }),
    );
  });

  it("should edit message without format", async () => {
    const mockApi = {
      editMessage: vi.fn().mockResolvedValue({}),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await editMessageMax({
      accountId: "test",
      messageId: "msg_nofmt",
      text: "plain edit",
    });

    expect(result.ok).toBe(true);
    expect(mockApi.editMessage).toHaveBeenCalledWith("msg_nofmt", {
      text: "plain edit",
      format: undefined,
    });
  });

  it("should return error on edit failure", async () => {
    const err = Object.assign(new Error("Not found"), { status: 404 });
    const mockApi = {
      editMessage: vi.fn().mockRejectedValue(err),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await editMessageMax({
      accountId: "test",
      messageId: "msg_2",
      text: "edit",
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("Not found");
  });
});

describe("deleteMessageMax", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should delete message", async () => {
    const mockApi = {
      deleteMessage: vi.fn().mockResolvedValue({}),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await deleteMessageMax({
      accountId: "test",
      messageId: "msg_del",
    });

    expect(result.ok).toBe(true);
    expect(result.messageId).toBe("msg_del");
    expect(mockApi.deleteMessage).toHaveBeenCalledWith("msg_del");
  });

  it("should return error on delete failure", async () => {
    const err = Object.assign(new Error("Forbidden"), { status: 403 });
    const mockApi = {
      deleteMessage: vi.fn().mockRejectedValue(err),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await deleteMessageMax({
      accountId: "test",
      messageId: "msg_del_fail",
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("Forbidden");
  });
});

describe("answerCallbackMax", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should answer callback with notification", async () => {
    const mockApi = {
      answerOnCallback: vi.fn().mockResolvedValue({}),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await answerCallbackMax({
      accountId: "test",
      callbackId: "cb_1",
      text: "Done!",
    });

    expect(result.ok).toBe(true);
    expect(mockApi.answerOnCallback).toHaveBeenCalledWith(
      "cb_1",
      expect.objectContaining({ notification: "Done!" }),
    );
  });

  it("should answer callback with message body", async () => {
    const mockApi = {
      answerOnCallback: vi.fn().mockResolvedValue({}),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await answerCallbackMax({
      accountId: "test",
      callbackId: "cb_2",
      message: { text: "Response text", format: "markdown" },
    });

    expect(mockApi.answerOnCallback).toHaveBeenCalledWith(
      "cb_2",
      expect.objectContaining({
        message: { text: "Response text", format: "markdown" },
      }),
    );
  });

  it("should send empty body when neither text nor message is provided", async () => {
    const mockApi = {
      answerOnCallback: vi.fn().mockResolvedValue({}),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await answerCallbackMax({
      accountId: "test",
      callbackId: "cb_empty",
    });

    expect(result.ok).toBe(true);
    expect(mockApi.answerOnCallback).toHaveBeenCalledWith("cb_empty", {});
  });

  it("should return error on callback failure", async () => {
    const err = Object.assign(new Error("Callback expired"), { status: 400 });
    const mockApi = {
      answerOnCallback: vi.fn().mockRejectedValue(err),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    const result = await answerCallbackMax({
      accountId: "test",
      callbackId: "cb_fail",
      text: "Too late",
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("Callback expired");
  });

  it("should include message without format when format is omitted", async () => {
    const mockApi = {
      answerOnCallback: vi.fn().mockResolvedValue({}),
    };
    vi.mocked(getMaxApi).mockReturnValue(mockApi as any);

    await answerCallbackMax({
      accountId: "test",
      callbackId: "cb_nofmt",
      message: { text: "Plain response" },
    });

    expect(mockApi.answerOnCallback).toHaveBeenCalledWith(
      "cb_nofmt",
      expect.objectContaining({
        message: { text: "Plain response" },
      }),
    );
  });
});
