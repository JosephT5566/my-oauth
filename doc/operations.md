# Operations

## Local Development

Install dependencies:

```sh
npm install
```

Start Wrangler dev:

```sh
npm start
```

or:

```sh
npm run dev
```

Generate Cloudflare Worker typings:

```sh
npm run cf-typegen
```

Run tests:

```sh
npm test
```

There are no test files in the current repo snapshot.

## Required Environment

The Worker expects these runtime values:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `TOKEN_STORE` KV binding

Do not commit Google client secrets or Cloudflare credentials.

## KV App Configuration

Create or update app config in remote KV:

```sh
npx wrangler kv key put --binding=TOKEN_STORE "config:<app_id>" '<json>' --remote
```

Example value:

```json
{
    "allowed_origins": ["http://localhost:3000", "https://app.example.com"],
    "gas_url": "https://script.google.com/macros/s/example/exec",
    "allowed_emails": ["user@example.com"]
}
```

If `allowed_emails` is omitted or empty, any Google account can complete login for that app.

## Deployment

Manual deploy:

```sh
npm run deploy
```

Automatic deploy:

- Push to `main`.
- GitHub Actions installs dependencies with `npm install`.
- Wrangler deploys with Cloudflare account and API token secrets.

## Troubleshooting

Invalid origin:

- Confirm the frontend origin exactly matches one value in `allowed_origins`.
- Include protocol and port where applicable.

Login redirects to `auth_error=unauthorized_email`:

- Add the Google account email to `allowed_emails`, or omit/empty the list if no allowlist is intended.

Refresh fails:

- The refresh token may be revoked or missing.
- The Worker clears session cookies and deletes the KV session on failed refresh paths.

TypeScript cannot find `worker-configuration.d.ts`:

- Run `npm run cf-typegen`.
