# Decisions And Risks

## Current Decisions

- Use Cloudflare Workers as the OAuth proxy runtime.
- Use Cloudflare KV for app config, temporary OAuth state, and sessions.
- Use one global Google OAuth client from environment secrets.
- Use `config:<app_id>` to support multiple frontend apps through one Worker.
- Validate `redirect_to` during login against `allowed_origins`.
- Use Google userinfo to enforce optional `allowed_emails`.
- Use subdomain-friendly cookies scoped to `josephtseng-tw.com`.
- Keep the browser-visible login flag separate from the HttpOnly session cookie.
- Proxy Google Apps Script calls through `/auth/:app_id/api/*`.

## Security-Sensitive Areas

- Redirect validation must stay strict. Avoid open redirects.
- CORS must only allow configured origins when credentials are included.
- Session IDs, access tokens, refresh tokens, and Google client secrets must not be logged or committed.
- Cookie domain, `SameSite`, `secure`, and `HttpOnly` choices affect SSO and frontend access.
- `logout` currently accepts any `redirect_to`; consider validating it if redirect abuse becomes a concern.
- `id_token` is documented as client-accessible in `README.md`, but code currently sets it as HttpOnly. Confirm intent before changing.

## Implementation Risks

- `AppConfig.client_id` exists in TypeScript but is not included in the README KV example and is not used by the OAuth flow.
- `package.json` does not list `cookie` or `nanoid`, even though `src/index.ts` imports them. They may be present transitively in `node_modules`, but direct runtime dependencies should normally be explicit.
- `tsconfig.json` references `worker-configuration.d.ts`, but the file is absent in the current snapshot.
- `id_token` is only refreshed when Google returns one from token refresh. Google refresh responses may not always include it.
- API proxy token injection currently targets POST JSON bodies. Other methods or non-JSON payloads do not receive token body injection.
- The proxy clones and parses the response as JSON to detect `TOKEN_EXPIRED`; non-JSON responses skip this refresh path.
- The Worker has no current automated test files.

## Suggested Test Coverage

- Login rejects missing app config and disallowed `redirect_to`.
- Callback rejects invalid state and redirects expected OAuth errors.
- Allowlisted and non-allowlisted emails behave correctly.
- `/me` enforces origin, refreshes expired access tokens, and clears invalid sessions.
- `/refresh` updates KV and cookie headers on success.
- `/logout` deletes session and clears all cookies.
- API proxy sets credentialed CORS headers, builds target URLs correctly, injects access tokens, and retries on `TOKEN_EXPIRED`.
