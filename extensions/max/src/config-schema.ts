import { MarkdownConfigSchema, ToolPolicySchema } from "openclaw/plugin-sdk";
import { z } from "zod";

const allowFromEntry = z.union([z.string(), z.number()]);

const groupConfigSchema = z.object({
  allow: z.boolean().optional(),
  enabled: z.boolean().optional(),
  tools: ToolPolicySchema,
});

const maxAccountSchema = z.object({
  name: z.string().optional(),
  enabled: z.boolean().optional(),
  markdown: MarkdownConfigSchema,
  botToken: z.string().optional(),
  dmPolicy: z.enum(["pairing", "allowlist", "open", "disabled"]).optional(),
  allowFrom: z.array(allowFromEntry).optional(),
  groupPolicy: z.enum(["disabled", "allowlist", "open"]).optional(),
  groups: z.object({}).catchall(groupConfigSchema).optional(),
  messagePrefix: z.string().optional(),
  responsePrefix: z.string().optional(),
  format: z.enum(["markdown", "html", "none"]).optional(),
});

export const MaxConfigSchema = maxAccountSchema.extend({
  accounts: z.object({}).catchall(maxAccountSchema).optional(),
  defaultAccount: z.string().optional(),
});
