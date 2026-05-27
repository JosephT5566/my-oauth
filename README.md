# About My-Oauth
This project is a Cloudflare Worker that acts as a secure OAuth 2.0 proxy for Google Authentication. It is designed to be deployed as a serverless function on Cloudflare's edge network.

Key features include:
-   Handling the complete Google OAuth 2.0 `authorization_code` flow, including token exchange.
-   Storing session data (access and refresh tokens) securely in a Cloudflare KV namespace.
-   Providing an `id_token` in a separate, client-accessible cookie for frontend use.
-   Automatically refreshing expired access tokens and the `id_token` using the stored refresh token.
-   Proxying authenticated API requests to a backend service (e.g., a Google Apps Script), injecting the user's Google access token.
-   Providing endpoints for login, logout, user profile retrieval, and manual token refresh.
-   Using subdomain-friendly cookies (`Domain`, `SameSite=Lax`) for seamless single-sign-on (SSO) experience across related applications.

## Routes
The following routes are exposed by the worker:

-   `GET /auth/:app_id/login?redirect_to=<URL>`
    -   **Description:** Initiates the Google OAuth login flow. On successful callback, it sets `session_id` (HttpOnly), `is_logged_in`, and `id_token` (HttpOnly) cookies.
    -   **`redirect_to` (optional):** The URL to redirect the user back to after a successful login. If not provided, it defaults to the first origin in the app's `allowed_origins` config. The origin of this URL must be in the `allowed_origins` list.
    -   **Callback errors:** If Google returns an error, token exchange fails, user info cannot be fetched, the Google account has no email, or the email is not allowed, the callback redirects back to `redirect_to` with `auth_error=<code>` instead of leaving the user on the auth callback URL. Current codes are `oauth_denied`, `token_exchange_failed`, `userinfo_failed`, `email_unavailable`, and `unauthorized_email`.

-   `GET /auth/:app_id/me`
    -   **Description:** Returns the authenticated user's Google profile information (name, email, picture) as a JSON object. Requires a valid session cookie. If the access token is expired, it will be refreshed, and all session cookies (including `id_token`) will be updated.

-   `GET /auth/:app_id/refresh`
    -   **Description:** Manually refreshes the user's access token and `id_token` using the stored refresh token. This route updates the session and extends all session cookies.

-   `GET /auth/:app_id/logout?redirect_to=<URL>`
    -   **Description:** Logs the user out by clearing their session data and all related cookies (`session_id`, `is_logged_in`, `id_token`).
    -   **`redirect_to` (optional):** A URL to redirect the user to after logout is complete.

-   `ALL /auth/:app_id/api/*`
    -   **Description:** Acts as an authenticated proxy. It forwards any request (`GET`, `POST`, etc.) to the `gas_url` configured for the `:app_id`. It automatically injects the user's `access_token` into the proxied request and handles token refresh if necessary.



# Cloudflare
## CDN
This worker is deployed on Cloudflare's edge network, which functions as a global Content Delivery Network (CDN). This ensures that authentication requests are handled by a server geographically close to the user, providing low-latency responses worldwide.

## Local test
Start the local
```
npx wrangler dev
```

## KV
Storing values in remote KV namespace ([doc](https://developers.cloudflare.com/kv/get-started/#4-interact-with-your-kv-namespace))

```
npx wrangler kv key put --binding=<Store name> "<KEY>" "<VALUE>" --remote
```

(Without `--remote`, it's just modifying local dev simulated resources)

### Key value pairs
The config keys are necessary for the proxy.
The key serves for the available entry and the following GAS url.

For example, key: `config:test-app`, and the url `/auth/test-app/...` is available.
And the value should be:
```json
{
  "allowed_origins": ["http://localhost:3000", "<ORIGIN_URL>"],
  "gas_url": "<GAS_URL>",
  "allowed_emails": ["user1@example.com", "user2@example.com"]
}
```
**Note:** If `allowed_emails` is provided and is not empty, only users authenticating with a matching Google account email will be granted a session. If the key is omitted or the array is empty, all users will be allowed.
