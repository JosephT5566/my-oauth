# About My-Oauth
This project is a Cloudflare Worker that acts as a secure OAuth 2.0 proxy for Google Authentication. It is designed to be deployed as a serverless function on Cloudflare's edge network.

Key features include:
-   Handling the complete Google OAuth 2.0 `authorization_code` flow, including token exchange.
-   Storing session data (access and refresh tokens) securely in a Cloudflare KV namespace.
-   Automatically refreshing expired access tokens using the stored refresh token.
-   Proxying authenticated API requests to a backend service (e.g., a Google Apps Script), injecting the user's Google access token.
-   Providing endpoints for login, logout, and retrieving user profile information.
-   Using subdomain-friendly cookies (`Domain`, `SameSite=Lax`) for seamless single-sign-on (SSO) experience across related applications.

## Routes
The following routes are exposed by the worker:

-   `GET /auth/:app_id/login?redirect_to=<URL>`
    -   **Description:** Initiates the Google OAuth login flow. It will redirect the user to the Google consent screen.
    -   **`redirect_to` (optional):** The URL to redirect the user back to after a successful login. If not provided, it defaults to the first origin in the app's `allowed_origins` config. The origin of this URL must be in the `allowed_origins` list.

-   `GET /auth/:app_id/logout?redirect_to=<URL>`
    -   **Description:** Logs the user out by clearing their session data and cookies.
    -   **`redirect_to` (optional):** A URL to redirect the user to after logout is complete.

-   `GET /auth/:app_id/me`
    -   **Description:** Returns the authenticated user's Google profile information (name, email, picture) as a JSON object. Requires a valid session cookie.

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

For example, key: `config:test-app`, and the url `/test/config/test-app/...` is available.
And the value should be:
```
{
  "allowed_origins": ["http://localhost:3000", "https://josephtseng-tw.github.io"],
  "gas_url": "<GAS_URL>"
}
```