import type { Bot } from "grammy";
import type { RuntimeEnv } from "../runtime.js";
import {
  normalizeTelegramCommandName,
  TELEGRAM_COMMAND_NAME_PATTERN,
} from "../config/telegram-custom-commands.js";
import { withTelegramApiErrorLogging } from "./api-logging.js";

export const TELEGRAM_MAX_COMMANDS = 100;

export type TelegramMenuCommand = {
  command: string;
  description: string;
};

type TelegramPluginCommandSpec = {
  name: string;
  description: string;
};

export function buildPluginTelegramMenuCommands(params: {
  specs: TelegramPluginCommandSpec[];
  existingCommands: Set<string>;
}): { commands: TelegramMenuCommand[]; issues: string[] } {
  const { specs, existingCommands } = params;
  const commands: TelegramMenuCommand[] = [];
  const issues: string[] = [];
  const pluginCommandNames = new Set<string>();

  for (const spec of specs) {
    const normalized = normalizeTelegramCommandName(spec.name);
    if (!normalized || !TELEGRAM_COMMAND_NAME_PATTERN.test(normalized)) {
      issues.push(
        `Plugin command "/${spec.name}" is invalid for Telegram (use a-z, 0-9, underscore; max 32 chars).`,
      );
      continue;
    }
    const description = spec.description.trim();
    if (!description) {
      issues.push(`Plugin command "/${normalized}" is missing a description.`);
      continue;
    }
    if (existingCommands.has(normalized)) {
      if (pluginCommandNames.has(normalized)) {
        issues.push(`Plugin command "/${normalized}" is duplicated.`);
      } else {
        issues.push(`Plugin command "/${normalized}" conflicts with an existing Telegram command.`);
      }
      continue;
    }
    pluginCommandNames.add(normalized);
    existingCommands.add(normalized);
    commands.push({ command: normalized, description });
  }

  return { commands, issues };
}

export function buildCappedTelegramMenuCommands(params: {
  allCommands: TelegramMenuCommand[];
  maxCommands?: number;
}): {
  commandsToRegister: TelegramMenuCommand[];
  totalCommands: number;
  maxCommands: number;
  overflowCount: number;
} {
  const { allCommands } = params;
  const maxCommands = params.maxCommands ?? TELEGRAM_MAX_COMMANDS;
  const totalCommands = allCommands.length;
  const overflowCount = Math.max(0, totalCommands - maxCommands);
  const commandsToRegister = allCommands.slice(0, maxCommands);
  return { commandsToRegister, totalCommands, maxCommands, overflowCount };
}

/**
 * RBAC-aware scoped menu registration.
 * When rbacScoping is provided:
 *   - Default scope (all users) sees only guestCommands
 *   - Each admin chat sees all commandsToRegister
 * When rbacScoping is not provided: backwards-compatible behavior.
 */
export function syncTelegramMenuCommands(params: {
  bot: Bot;
  runtime: RuntimeEnv;
  commandsToRegister: TelegramMenuCommand[];
  rbacScoping?: {
    adminChatIds: number[];
    guestCommands: TelegramMenuCommand[];
  };
}): void {
  const { bot, runtime, commandsToRegister, rbacScoping } = params;
  const sync = async () => {
    // Delete default scope commands first
    if (typeof bot.api.deleteMyCommands === "function") {
      await withTelegramApiErrorLogging({
        operation: "deleteMyCommands",
        runtime,
        fn: () => bot.api.deleteMyCommands(),
      }).catch(() => {});
    }

    if (!rbacScoping) {
      // No RBAC scoping — register all commands for everyone (backwards compatible)
      if (commandsToRegister.length > 0) {
        await withTelegramApiErrorLogging({
          operation: "setMyCommands",
          runtime,
          fn: () => bot.api.setMyCommands(commandsToRegister),
        });
      }
      return;
    }

    // RBAC scoping: guest commands for default scope, full commands for admin chats
    const { adminChatIds, guestCommands } = rbacScoping;

    if (guestCommands.length > 0) {
      await withTelegramApiErrorLogging({
        operation: "setMyCommands(default)",
        runtime,
        fn: () =>
          bot.api.setMyCommands(guestCommands, {
            scope: { type: "default" },
          }),
      });
    }

    // Set full command menu for each admin user's private chat
    for (const chatId of adminChatIds) {
      // Delete admin-scoped commands first (clean slate)
      await withTelegramApiErrorLogging({
        operation: `deleteMyCommands(chat:${chatId})`,
        runtime,
        fn: () =>
          bot.api.deleteMyCommands({
            scope: { type: "chat", chat_id: chatId },
          }),
      }).catch(() => {});

      if (commandsToRegister.length > 0) {
        await withTelegramApiErrorLogging({
          operation: `setMyCommands(chat:${chatId})`,
          runtime,
          fn: () =>
            bot.api.setMyCommands(commandsToRegister, {
              scope: { type: "chat", chat_id: chatId },
            }),
        });
      }
    }

    runtime.log?.(
      `rbac: menu scoped — ${guestCommands.length} guest commands (default), ` +
        `${commandsToRegister.length} admin commands for ${adminChatIds.length} admin(s)`,
    );
  };

  void sync().catch(() => {});
}
