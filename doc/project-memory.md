# Project Memory

## Snapshot

`my-oauth` is a Cloudflare Worker OAuth proxy for Google authentication. It lets multiple frontend apps use one Worker for Google login and authenticated backend calls.

The Worker:

- Starts Google OAuth login for `/auth/:app_id/login`.
- Handles Google's authorization callback at `/auth/:app_id/callback`.
- Stores access and refresh tokens in Cloudflare KV under `session:<session_id>`.
- Stores short-lived OAuth state in KV under `state:<state>`.
- Reads app configuration from KV under `config:<app_id>`.
- Sets cookies for browser session state.
- Refreshes expired access tokens with the stored refresh token.
- Proxies authenticated API calls to a configured Google Apps Script URL.

## Current Stack

- TypeScript
- Cloudflare Workers
- Wrangler
- Cloudflare KV
- `itty-router`
- `nanoid`
- `cookie`

## Current Repository Shape

- `src/index.ts`: Worker implementation.
- `README.md`: public overview, routes, and KV config example.
- `wrangler.jsonc`: Cloudflare Worker configuration.
- `.github/workflows/deploy.yml`: deployment workflow.
- `.vscode/settings.json`: local editor formatting settings.

## User-Facing Routes

- `GET /ok`: health check returning `Success!`.
- `GET /auth/:app_id/login?redirect_to=<URL>`: starts Google OAuth.
- `GET /auth/:app_id/callback`: completes OAuth and sets session cookies.
- `GET /auth/:app_id/me`: returns Google user profile JSON.
- `GET /auth/:app_id/refresh`: manually refreshes session tokens.
- `GET /auth/:app_id/logout?redirect_to=<URL>`: clears session and redirects.
- `ALL /auth/:app_id/api/*`: proxies authenticated requests to app `gas_url`.

## KV Data

`config:<app_id>` value:

```json
{
    "allowed_origins": ["http://localhost:3000", "https://example.com"],
    "gas_url": "https://script.google.com/macros/s/example/exec",
    "allowed_emails": ["user@example.com"]
}
```

The TypeScript interface also includes `client_id`, but the login/token flows currently use global `env.GOOGLE_CLIENT_ID` instead.

`session:<session_id>` value:

```json
{
    "access_token": "<google-access-token>",
    "refresh_token": "<google-refresh-token>"
}
```

`state:<state>` value:

```json
{
    "app_id": "<app-id>",
    "redirectTo": "https://allowed-origin.example/path"
}
```

## Cookies

The Worker currently sets:

- `session_id`: HttpOnly, secure, `SameSite=Lax`, domain `josephtseng-tw.com`, path `/`, max age 7 days.
- `is_logged_in`: secure, `SameSite=Lax`, domain `josephtseng-tw.com`, path `/`, max age 7 days.
- `id_token`: HttpOnly, secure, `SameSite=Lax`, domain `josephtseng-tw.com`, path `/`, max age 1 hour.

Session KV entries are stored for 30 days.
