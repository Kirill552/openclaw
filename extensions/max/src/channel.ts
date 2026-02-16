import type {
  ChannelAccountSnapshot,
  ChannelDirectoryEntry,
  ChannelDock,
  ChannelGroupContext,
  ChannelPlugin,
  OpenClawConfig,
  GroupToolPolicyConfig,
} from "openclaw/plugin-sdk";
import {
  applyAccountNameToChannelSection,
  buildChannelConfigSchema,
  DEFAULT_ACCOUNT_ID,
  deleteAccountFromConfigSection,
  formatPairingApproveHint,
  migrateBaseNameToDefaultAccount,
  normalizeAccountId,
  setAccountEnabledInConfigSection,
} from "openclaw/plugin-sdk";
import type { ResolvedMaxAccount } from "./types.js";
import {
  listMaxAccountIds,
  resolveDefaultMaxAccountId,
  resolveMaxAccountSync,
} from "./accounts.js";
import { MaxConfigSchema } from "./config-schema.js";
import { maxOnboardingAdapter } from "./onboarding.js";
import { probeMaxBot, getMaxApi } from "./bot.js";
import { sendTextMax, editMessageMax } from "./send.js";
import { sendMediaMax } from "./media.js";
import { monitorMaxProvider } from "./monitor.js";
import { collectMaxStatusIssues } from "./status-issues.js";

const meta = {
  id: "max",
  label: "MAX Messenger",
  selectionLabel: "MAX Messenger",
  docsPath: "/channels/max",
  docsLabel: "max",
  blurb: "MAX Messenger bot via official Bot API.",
  aliases: ["maxmessenger"],
  order: 20,
  quickstartAllowFrom: true,
};

function mapUser(params: {
  id: string;
  name?: string | null;
  avatarUrl?: string | null;
  raw?: unknown;
}): ChannelDirectoryEntry {
  return {
    kind: "user",
    id: params.id,
    name: params.name ?? undefined,
    avatarUrl: params.avatarUrl ?? undefined,
    raw: params.raw,
  };
}

function resolveMaxGroupToolPolicy(
  params: ChannelGroupContext,
): GroupToolPolicyConfig | undefined {
  const account = resolveMaxAccountSync({
    cfg: params.cfg,
    accountId: params.accountId ?? undefined,
  });
  const groups = account.config.groups ?? {};
  const groupId = params.groupId?.trim();
  const groupChannel = params.groupChannel?.trim();
  const candidates = [groupId, groupChannel, "*"].filter((value): value is string =>
    Boolean(value),
  );
  for (const key of candidates) {
    const entry = groups[key];
    if (entry?.tools) {
      return entry.tools;
    }
  }
  return undefined;
}

export const maxDock: ChannelDock = {
  id: "max",
  capabilities: {
    chatTypes: ["direct", "group", "channel"],
    media: true,
    blockStreaming: false,
    reactions: false,
    threads: false,
    nativeCommands: true,
    edit: true,
    unsend: true,
    reply: true,
    polls: false,
  },
  outbound: { textChunkLimit: 4000 },
  config: {
    resolveAllowFrom: ({ cfg, accountId }) =>
      (resolveMaxAccountSync({ cfg: cfg, accountId }).config.allowFrom ?? []).map((entry) =>
        String(entry),
      ),
    formatAllowFrom: ({ allowFrom }) =>
      allowFrom
        .map((entry) => String(entry).trim())
        .filter(Boolean)
        .map((entry) => entry.replace(/^(max|maxmessenger):/i, ""))
        .map((entry) => entry.toLowerCase()),
  },
  groups: {
    resolveRequireMention: () => false,
    resolveToolPolicy: resolveMaxGroupToolPolicy,
  },
  threading: {
    resolveReplyToMode: () => "off",
  },
};

export const maxPlugin: ChannelPlugin<ResolvedMaxAccount> = {
  id: "max",
  meta,
  onboarding: maxOnboardingAdapter,
  capabilities: {
    chatTypes: ["direct", "group", "channel"],
    media: true,
    reactions: false,
    threads: false,
    polls: false,
    nativeCommands: true,
    blockStreaming: false,
    edit: true,
    unsend: true,
    reply: true,
  },
  reload: { configPrefixes: ["channels.max"] },
  configSchema: buildChannelConfigSchema(MaxConfigSchema),
  config: {
    listAccountIds: (cfg) => listMaxAccountIds(cfg),
    resolveAccount: (cfg, accountId) => resolveMaxAccountSync({ cfg: cfg, accountId }),
    defaultAccountId: (cfg) => resolveDefaultMaxAccountId(cfg),
    setAccountEnabled: ({ cfg, accountId, enabled }) =>
      setAccountEnabledInConfigSection({
        cfg: cfg,
        sectionKey: "max",
        accountId,
        enabled,
        allowTopLevel: true,
      }),
    deleteAccount: ({ cfg, accountId }) =>
      deleteAccountFromConfigSection({
        cfg: cfg,
        sectionKey: "max",
        accountId,
        clearBaseFields: [
          "botToken",
          "name",
          "dmPolicy",
          "allowFrom",
          "groupPolicy",
          "groups",
          "messagePrefix",
        ],
      }),
    isConfigured: async (account) => Boolean(account.token),
    describeAccount: (account): ChannelAccountSnapshot => ({
      accountId: account.accountId,
      name: account.name,
      enabled: account.enabled,
      configured: Boolean(account.token),
    }),
    resolveAllowFrom: ({ cfg, accountId }) =>
      (resolveMaxAccountSync({ cfg: cfg, accountId }).config.allowFrom ?? []).map((entry) =>
        String(entry),
      ),
    formatAllowFrom: ({ allowFrom }) =>
      allowFrom
        .map((entry) => String(entry).trim())
        .filter(Boolean)
        .map((entry) => entry.replace(/^(max|maxmessenger):/i, ""))
        .map((entry) => entry.toLowerCase()),
  },
  security: {
    resolveDmPolicy: ({ account }) => ({
      policy: account.config.dmPolicy ?? "open",
      allowFrom: account.config.allowFrom ?? [],
      policyPath: "channels.max.dmPolicy",
      allowFromPath: "channels.max",
      approveHint: formatPairingApproveHint("max"),
      normalizeEntry: (raw) => raw.replace(/^(max|maxmessenger):/i, ""),
    }),
  },
  groups: {
    resolveRequireMention: () => false,
    resolveToolPolicy: resolveMaxGroupToolPolicy,
  },
  threading: {
    resolveReplyToMode: () => "off",
  },
  setup: {
    resolveAccountId: ({ accountId }) => normalizeAccountId(accountId),
    applyAccountName: ({ cfg, accountId, name }) =>
      applyAccountNameToChannelSection({
        cfg: cfg,
        channelKey: "max",
        accountId,
        name,
      }),
    validateInput: () => null,
    applyAccountConfig: ({ cfg, accountId, input }) => {
      const namedConfig = applyAccountNameToChannelSection({
        cfg: cfg,
        channelKey: "max",
        accountId,
        name: input.name,
      });
      const next =
        accountId !== DEFAULT_ACCOUNT_ID
          ? migrateBaseNameToDefaultAccount({
              cfg: namedConfig,
              channelKey: "max",
            })
          : namedConfig;
      if (accountId === DEFAULT_ACCOUNT_ID) {
        return {
          ...next,
          channels: {
            ...next.channels,
            max: {
              ...next.channels?.max,
              enabled: true,
            },
          },
        } as OpenClawConfig;
      }
      return {
        ...next,
        channels: {
          ...next.channels,
          max: {
            ...next.channels?.max,
            enabled: true,
            accounts: {
              ...next.channels?.max?.accounts,
              [accountId]: {
                ...next.channels?.max?.accounts?.[accountId],
                enabled: true,
              },
            },
          },
        },
      } as OpenClawConfig;
    },
  },
  messaging: {
    normalizeTarget: (raw) => {
      const trimmed = raw?.trim();
      if (!trimmed) {
        return undefined;
      }
      return trimmed.replace(/^(max|maxmessenger):/i, "");
    },
    targetResolver: {
      looksLikeId: (raw) => /^\d{3,}$/.test(raw.trim()),
      hint: "<chatId>",
    },
  },
  directory: {
    self: async ({ accountId, cfg }) => {
      const account = resolveMaxAccountSync({ cfg: cfg ?? ({} as OpenClawConfig), accountId });
      if (!account.token) return null;
      const probe = await probeMaxBot(account.token);
      if (!probe.ok || !probe.name) return null;
      return mapUser({ id: "self", name: probe.name, raw: probe });
    },
    listPeers: async ({ accountId }) => {
      try {
        const api = getMaxApi(accountId ?? "");
        const chats = await api.getAllChats();
        return (chats.chats ?? [])
          .filter((c) => c.type === "dialog")
          .map((c) =>
            mapUser({
              id: String(c.chat_id ?? ""),
              name: String(c.title ?? ""),
              raw: c,
            }),
          );
      } catch {
        return [];
      }
    },
    listGroups: async ({ accountId }) => {
      try {
        const api = getMaxApi(accountId ?? "");
        const chats = await api.getAllChats();
        return (chats.chats ?? [])
          .filter((c) => c.type === "chat")
          .map((c) => ({
            kind: "group" as const,
            id: String(c.chat_id ?? ""),
            name: String(c.title ?? ""),
            raw: c,
          }));
      } catch {
        return [];
      }
    },
    listGroupMembers: async ({ accountId, groupId }) => {
      try {
        const api = getMaxApi(accountId ?? "");
        const members = await api.getChatMembers(Number(groupId));
        return (members.members ?? []).map((m) =>
          mapUser({
            id: String(m.user_id ?? ""),
            name: String(m.name ?? ""),
            raw: m,
          }),
        );
      } catch {
        return [];
      }
    },
  },
  resolver: {
    resolveTargets: async ({ inputs }) => {
      return inputs.map((input) => {
        const trimmed = input.trim();
        if (!trimmed) {
          return { input, resolved: false, note: "empty input" };
        }
        if (/^\d+$/.test(trimmed)) {
          return { input, resolved: true, id: trimmed };
        }
        return { input, resolved: false, note: "not a numeric ID" };
      });
    },
  },
  pairing: {
    idLabel: "maxUserId",
    normalizeAllowEntry: (entry) => entry.replace(/^(max|maxmessenger):/i, ""),
    notifyApproval: async () => {},
  },
  outbound: {
    deliveryMode: "direct",
    chunkerMode: "markdown",
    textChunkLimit: 4000,
    sendText: async ({ to, text, accountId, cfg }) => {
      const account = resolveMaxAccountSync({ cfg: cfg, accountId });
      const chatId = Number(to);
      if (isNaN(chatId)) {
        return { channel: "max", ok: false, messageId: "", error: new Error("Invalid chatId") };
      }
      const result = await sendTextMax({
        accountId: account.accountId,
        chatId,
        text,
        format: account.config.format ?? "markdown",
      });
      return {
        channel: "max",
        ok: result.ok,
        messageId: result.messageId ?? "",
        error: result.error ? new Error(result.error) : undefined,
      };
    },
    sendMedia: async ({ to, text, mediaUrl, accountId, cfg }) => {
      const account = resolveMaxAccountSync({ cfg: cfg, accountId });
      const chatId = Number(to);
      if (isNaN(chatId)) {
        return { channel: "max", ok: false, messageId: "", error: new Error("Invalid chatId") };
      }
      if (!mediaUrl) {
        return { channel: "max", ok: false, messageId: "", error: new Error("No media URL") };
      }
      const result = await sendMediaMax({
        accountId: account.accountId,
        chatId,
        mediaUrl,
        caption: text,
        format: account.config.format ?? "markdown",
      });
      return {
        channel: "max",
        ok: result.ok,
        messageId: result.messageId ?? "",
        error: result.error ? new Error(result.error) : undefined,
      };
    },
  },
  streaming: {
    blockStreamingCoalesceDefaults: {
      minChars: 60,
      idleMs: 500,
    },
  },
  status: {
    defaultRuntime: {
      accountId: DEFAULT_ACCOUNT_ID,
      running: false,
      lastStartAt: null,
      lastStopAt: null,
      lastError: null,
    },
    collectStatusIssues: collectMaxStatusIssues,
    buildChannelSummary: ({ snapshot }) => ({
      configured: snapshot.configured ?? false,
      running: snapshot.running ?? false,
      lastStartAt: snapshot.lastStartAt ?? null,
      lastStopAt: snapshot.lastStopAt ?? null,
      lastError: snapshot.lastError ?? null,
      probe: snapshot.probe,
      lastProbeAt: snapshot.lastProbeAt ?? null,
    }),
    probeAccount: async ({ account }) => {
      const result = await probeMaxBot(account.token);
      return { ok: result.ok, name: result.name, error: result.error };
    },
    buildAccountSnapshot: async ({ account, runtime }) => {
      const configured = Boolean(account.token);
      return {
        accountId: account.accountId,
        name: account.name,
        enabled: account.enabled,
        configured,
        running: runtime?.running ?? false,
        lastStartAt: runtime?.lastStartAt ?? null,
        lastStopAt: runtime?.lastStopAt ?? null,
        lastError: configured ? (runtime?.lastError ?? null) : "missing bot token",
        lastInboundAt: runtime?.lastInboundAt ?? null,
        lastOutboundAt: runtime?.lastOutboundAt ?? null,
        dmPolicy: account.config.dmPolicy ?? "open",
      };
    },
  },
  gateway: {
    startAccount: async (ctx) => {
      const account = ctx.account;
      if (!account.token) {
        throw new Error(`MAX account ${account.accountId} has no bot token`);
      }
      return monitorMaxProvider({
        account,
        config: ctx.cfg,
        abortSignal: ctx.abortSignal,
        setStatus: (patch) => ctx.setStatus({ accountId: ctx.account.accountId, ...patch }),
      });
    },
    stopAccount: async (ctx) => {
      ctx.setStatus({
        accountId: ctx.account.accountId,
        running: false,
        lastStopAt: Date.now(),
      });
    },
    logoutAccount: async (_ctx) => {
      return {
        cleared: true,
        loggedOut: true,
        message: "MAX bot stopped",
      };
    },
  },
};

/**
 * Streaming-via-edit helper. Sends a new message or edits an existing one,
 * enabling incremental "draft" updates while an LLM response is streaming.
 */
export async function maxStreamingDraft(params: {
  to: string;
  text: string;
  accountId: string;
  cfg: OpenClawConfig;
  existingMessageId?: string;
}): Promise<{ ok: boolean; messageId: string }> {
  const account = resolveMaxAccountSync({ cfg: params.cfg, accountId: params.accountId });
  const chatId = Number(params.to);
  if (isNaN(chatId)) return { ok: false, messageId: "" };

  if (params.existingMessageId) {
    const result = await editMessageMax({
      accountId: account.accountId,
      messageId: params.existingMessageId,
      text: params.text,
      format: account.config.format ?? "markdown",
    });
    return { ok: result.ok, messageId: params.existingMessageId };
  }

  const result = await sendTextMax({
    accountId: account.accountId,
    chatId,
    text: params.text,
    format: account.config.format ?? "markdown",
  });
  return { ok: result.ok, messageId: result.messageId ?? "" };
}

export type { ResolvedMaxAccount };
