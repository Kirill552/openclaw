export type MaxAccountConfig = {
  enabled?: boolean;
  name?: string;
  botToken?: string;
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  allowFrom?: Array<string | number>;
  groupPolicy?: "open" | "allowlist" | "disabled";
  groups?: Record<
    string,
    { allow?: boolean; enabled?: boolean; tools?: { allow?: string[]; deny?: string[] } }
  >;
  messagePrefix?: string;
  responsePrefix?: string;
  format?: "markdown" | "html";
};

export type MaxConfig = {
  enabled?: boolean;
  name?: string;
  botToken?: string;
  defaultAccount?: string;
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  allowFrom?: Array<string | number>;
  groupPolicy?: "open" | "allowlist" | "disabled";
  groups?: Record<
    string,
    { allow?: boolean; enabled?: boolean; tools?: { allow?: string[]; deny?: string[] } }
  >;
  messagePrefix?: string;
  responsePrefix?: string;
  format?: "markdown" | "html";
  accounts?: Record<string, MaxAccountConfig>;
};

export type ResolvedMaxAccount = {
  accountId: string;
  name?: string;
  enabled: boolean;
  token: string;
  config: MaxAccountConfig;
};

export type MaxBotOptions = {
  token: string;
  accountId: string;
  format?: "markdown" | "html";
};

export type MaxSendResult = {
  ok: boolean;
  messageId?: string;
  error?: string;
};

export type MaxMessageContext = {
  userId: string;
  chatId: string;
  messageId: string;
  text?: string;
  attachments?: MaxAttachment[];
  callback?: {
    payload: string;
    callbackId: string;
  };
  raw: unknown;
};

export type MaxAttachment = {
  type: "image" | "video" | "audio" | "file" | "contact" | "location";
  payload: unknown;
  url?: string | null;
};

export type MaxBotInstance = {
  bot: unknown;
  accountId: string;
  token: string;
};

export type MaxBotEvent = {
  type: "bot_started" | "bot_stopped" | "message_edited" | "message_removed"
    | "user_added" | "user_removed" | "chat_title_changed";
  userId: string;
  chatId: string;
  messageId?: string;
  text?: string;
  raw: unknown;
};
