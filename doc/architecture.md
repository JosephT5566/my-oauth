# Architecture

## Request Flow

### Login

`GET /auth/:app_id/login` loads `config:<app_id>` from KV, validates `redirect_to` when provided, stores a short-lived state payload in KV, then redirects to Google OAuth.

OAuth parameters currently include:

- `client_id`: `env.GOOGLE_CLIENT_ID`
- `redirect_uri`: current request origin plus `/auth/:app_id/callback`
- `scope`: OpenID, user email, user profile, and Google Apps Script projects scope
- `response_type`: `code`
- `access_type`: `offline`
- `prompt`: `consent`

### Callback

`GET /auth/:app_id/callback` validates the `state` value against KV, exchanges the authorization code with Google, optionally enforces `allowed_emails`, stores the session in KV, sets cookies, and redirects to the original destination.

Callback errors redirect back to the intended destination with `auth_error=<code>` when the Worker can safely recover the destination from state.

Current error codes:

- `oauth_denied`
- `token_exchange_failed`
- `userinfo_failed`
- `email_unavailable`
- `unauthorized_email`

### Me

`GET /auth/:app_id/me` validates origin, loads `session_id` from cookies, fetches Google userinfo with the access token, and returns profile JSON. If Google returns `401` and the session has a refresh token, it refreshes tokens, updates KV, updates cookies, and retries userinfo.

### Refresh

`GET /auth/:app_id/refresh` validates origin and session, refreshes the Google access token, stores updated session data, refreshes cookies, and returns `{ "success": true }`.

### Logout

`GET /auth/:app_id/logout` deletes `session:<session_id>` when present, clears all auth cookies, and redirects to `redirect_to` or an empty location.

### API Proxy

`ALL /auth/:app_id/api/*` validates session, maps the remaining path onto the configured `gas_url`, forwards the request, and injects the current Google access token into POST JSON bodies as `access_token`.

When the proxied response body is JSON and includes `errorCode: "TOKEN_EXPIRED"`, the Worker refreshes the access token, updates KV/cookies, and retries the proxy request.

## CORS Model

Preflight requests resolve `app_id` from the path and require the request `Origin` to be in `config.allowed_origins`.

Authenticated route responses set:

- `Access-Control-Allow-Origin` to the validated origin.
- `Access-Control-Allow-Credentials` to `true`.

Do not loosen CORS to wildcard origins while cookies are involved.

## Storage Model

Cloudflare KV binding: `TOKEN_STORE`

Key prefixes:

- `config:` for app configuration.
- `state:` for short-lived OAuth state. Current TTL is 300 seconds.
- `session:` for session token storage. Current TTL is 30 days.

## Deployment

`wrangler.jsonc` points the Worker entrypoint at `src/index.ts` and binds the remote KV namespace to `TOKEN_STORE`.

GitHub Actions deploys on pushes to `main` using `cloudflare/wrangler-action@v3`. Required GitHub secrets are:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
