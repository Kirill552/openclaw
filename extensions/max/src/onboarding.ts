import type {
  ChannelOnboardingAdapter,
  ChannelOnboardingDmPolicy,
  OpenClawConfig,
  WizardPrompter,
} from "openclaw/plugin-sdk";
import {
  addWildcardAllowFrom,
  DEFAULT_ACCOUNT_ID,
  normalizeAccountId,
  promptAccountId,
} from "openclaw/plugin-sdk";
import {
  listMaxAccountIds,
  resolveDefaultMaxAccountId,
  resolveMaxAccountSync,
} from "./accounts.js";
import { probeMaxBot } from "./bot.js";

const channel = "max" as const;

function setMaxDmPolicy(
  cfg: OpenClawConfig,
  dmPolicy: "pairing" | "allowlist" | "open" | "disabled",
): OpenClawConfig {
  const allowFrom =
    dmPolicy === "open" ? addWildcardAllowFrom(cfg.channels?.max?.allowFrom) : undefined;
  return {
    ...cfg,
    channels: {
      ...cfg.channels,
      max: {
        ...cfg.channels?.max,
        dmPolicy,
        ...(allowFrom ? { allowFrom } : {}),
      },
    },
  } as OpenClawConfig;
}

async function noteMaxHelp(prompter: WizardPrompter): Promise<void> {
  await prompter.note(
    [
      "MAX Messenger bot setup.",
      "",
      "Prerequisites:",
      "1) Create a bot in MAX Messenger",
      "2) Get your bot token",
      "",
      "Docs: https://docs.openclaw.ai/channels/max",
    ].join("\n"),
    "MAX Messenger Setup",
  );
}

async function promptMaxBotToken(
  prompter: WizardPrompter,
  initialValue?: string,
): Promise<string | undefined> {
  const token = await prompter.text({
    message: "MAX bot token",
    placeholder: "Paste your bot token here",
    initialValue,
    validate: (value) => {
      const trimmed = String(value ?? "").trim();
      if (!trimmed) {
        return "Required";
      }
      return undefined;
    },
  });
  const result = String(token).trim();
  return result || undefined;
}

const dmPolicy: ChannelOnboardingDmPolicy = {
  label: "MAX Messenger",
  channel,
  policyKey: "channels.max.dmPolicy",
  allowFromKey: "channels.max.allowFrom",
  getCurrent: (cfg) => (cfg.channels?.max?.dmPolicy ?? "open") as "open",
  setPolicy: (cfg, policy) => setMaxDmPolicy(cfg, policy),
  promptAllowFrom: async ({ cfg, prompter, accountId }) => {
    const id =
      accountId && normalizeAccountId(accountId)
        ? (normalizeAccountId(accountId) ?? DEFAULT_ACCOUNT_ID)
        : resolveDefaultMaxAccountId(cfg);
    
    const allowFrom = await prompter.text({
      message: "Allow from (comma-separated user IDs, or * for all)",
      placeholder: "*",
      initialValue: "*",
    });
    
    const entries = String(allowFrom)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    
    if (id === DEFAULT_ACCOUNT_ID) {
      return {
        ...cfg,
        channels: {
          ...cfg.channels,
          max: {
            ...cfg.channels?.max,
            enabled: true,
            dmPolicy: "allowlist" as const,
            allowFrom: entries,
          },
        },
      } as OpenClawConfig;
    }
    
    return {
      ...cfg,
      channels: {
        ...cfg.channels,
        max: {
          ...cfg.channels?.max,
          enabled: true,
          accounts: {
            ...cfg.channels?.max?.accounts,
            [id]: {
              ...cfg.channels?.max?.accounts?.[id],
              enabled: true,
              dmPolicy: "allowlist" as const,
              allowFrom: entries,
            },
          },
        },
      },
    } as OpenClawConfig;
  },
};

export const maxOnboardingAdapter: ChannelOnboardingAdapter = {
  channel,
  dmPolicy,
  getStatus: async ({ cfg }) => {
    const ids = listMaxAccountIds(cfg);
    let configured = false;
    let botName: string | undefined;
    
    for (const accountId of ids) {
      const account = resolveMaxAccountSync({ cfg: cfg, accountId });
      if (account.token) {
        const probe = await probeMaxBot(account.token);
        if (probe.ok) {
          configured = true;
          botName = probe.name;
          break;
        }
      }
    }
    
    return {
      channel,
      configured,
      statusLines: [`MAX Messenger: ${configured ? (botName ? `configured (${botName})` : "configured") : "needs bot token"}`],
      selectionHint: configured ? "recommended · configured" : "recommended · needs token",
      quickstartScore: configured ? 1 : 10,
    };
  },
  configure: async ({
    cfg,
    prompter,
    accountOverrides,
    shouldPromptAccountIds,
    forceAllowFrom,
  }) => {
    const maxOverride = accountOverrides.max?.trim();
    const defaultAccountId = resolveDefaultMaxAccountId(cfg);
    let accountId = maxOverride ? normalizeAccountId(maxOverride) : defaultAccountId;
    
    if (shouldPromptAccountIds && !maxOverride) {
      accountId = await promptAccountId({
        cfg: cfg,
        prompter,
        label: "MAX Messenger",
        currentId: accountId,
        listAccountIds: listMaxAccountIds,
        defaultAccountId,
      });
    }
    
    let next = cfg;
    const account = resolveMaxAccountSync({ cfg: next, accountId });
    const existingToken = account.token || process.env.MAX_BOT_TOKEN?.trim();
    
    let token = existingToken;
    
    if (!existingToken) {
      await noteMaxHelp(prompter);
      const newToken = await promptMaxBotToken(prompter);
      
      if (!newToken) {
        return { cfg: next, accountId };
      }
      
      token = newToken;
      
      const probe = await probeMaxBot(token);
      if (!probe.ok) {
        await prompter.note(
          `Token verification failed: ${probe.error}`,
          "Error",
        );
        return { cfg: next, accountId };
      }
      
      await prompter.note(
        `Bot verified: ${probe.name ?? "Unknown"}`,
        "Success",
      );
    } else {
      const probe = await probeMaxBot(existingToken);
      if (probe.ok && probe.name) {
        await prompter.note(
          `Bot already configured: ${probe.name}`,
          "MAX Messenger",
        );
      }
    }
    
    if (accountId === DEFAULT_ACCOUNT_ID) {
      next = {
        ...next,
        channels: {
          ...next.channels,
          max: {
            ...next.channels?.max,
            enabled: true,
            botToken: token,
          },
        },
      } as OpenClawConfig;
    } else {
      next = {
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
                botToken: token,
              },
            },
          },
        },
      } as OpenClawConfig;
    }
    
    if (forceAllowFrom) {
      const dmPolicyResult = await prompter.select({
        message: "Who can message this bot?",
        options: [
          { value: "open", label: "Anyone" },
          { value: "allowlist", label: "Specific users" },
        ],
        initialValue: "open",
      });
      
      if (dmPolicyResult === "allowlist" && dmPolicy.promptAllowFrom) {
        next = await dmPolicy.promptAllowFrom({
          cfg: next,
          prompter,
          accountId,
        });
      } else {
        next = setMaxDmPolicy(next, "open");
      }
    }
    
    return { cfg: next, accountId };
  },
};
