# Deploying CodeSentry to Fly.io

## Prerequisites

- [Fly CLI](https://fly.io/docs/getting-started/installing-flyctl/) installed and authenticated
- GitHub App configured with webhook secret, private key, and App ID
- Anthropic API key

## Steps

### 1. Launch the app

```bash
fly launch --name codesentry --region sjc
```

### 2. Create a persistent volume for SQLite

```bash
fly volumes create codesentry_data --size 1
```

### 3. Set secrets

```bash
fly secrets set \
  GITHUB_APP_ID=xxx \
  GITHUB_PRIVATE_KEY="$(cat private-key.pem)" \
  GITHUB_WEBHOOK_SECRET=xxx \
  ANTHROPIC_API_KEY=xxx \
  IS_PRODUCTION=true
```

### 4. Deploy

```bash
fly deploy
```

### 5. Update the GitHub App webhook URL

In your GitHub App settings, set the webhook URL to:

```
https://codesentry.fly.dev/webhook
```

### 6. Verify

- Health check: `curl https://codesentry.fly.dev/health`
- Landing page: open `https://codesentry.fly.dev/` in a browser
- Open a test PR on a connected repository to confirm the full analysis runs
