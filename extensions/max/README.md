# MAX Messenger Channel Plugin

OpenClaw channel plugin for MAX Messenger via official Bot API.

## Features

- Text messages with Markdown/HTML formatting
- Media support (images, videos, audio, files)
- Inline keyboard buttons
- Message editing and deletion
- Callback button handling
- Bot start events

## Configuration

### openclaw.yaml

```yaml
channels:
  max:
    enabled: true
    botToken: ${MAX_BOT_TOKEN}
    dmPolicy: open
    allowFrom: ["*"]
    format: markdown
    accounts:
      default:
        botToken: ${MAX_BOT_TOKEN}
```

### Environment Variables

```env
MAX_BOT_TOKEN=your_max_bot_token
```

## MAX Bot API SDK

- Package: `@maxhub/max-bot-api` v0.2.2
- GitHub: https://github.com/max-messenger/max-bot-api-client-ts
- API Base: `https://platform-api.max.ru`

## Rate Limits

- Rate limit: 30 RPS
- Text message: ~4000 characters
- Inline keyboard: up to 210 buttons (30 rows x 7)
