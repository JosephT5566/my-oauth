import { IRequest, AutoRouter } from "itty-router";
import { nanoid } from "nanoid";
import * as cookie from "cookie";

const router = AutoRouter();

interface AppConfig {
    client_id: string;
    allowed_origins: string[];
    gas_url: string;
}

interface Session {
    access_token: string;
    refresh_token?: string;
}

interface GASResponse {
    ok: boolean;
    result?: any;
    error?: string;
    errorCode?: string;
}

router.get("/", () => "Success!");

// CORS Preflight
router.options("*", async (request: IRequest, env: Env) => {
    const origin = request.headers.get("Origin");
    if (!origin) {
        return new Response("Missing Origin header", { status: 400 });
    }

    const url = new URL(request.url);
    const app_id = url.pathname.split("/")[2];

    const config: AppConfig | null = await env.TOKEN_STORE.get(
        `config:${app_id}`,
        "json",
    );
    if (!config || !config.allowed_origins.includes(origin)) {
        return new Response("Invalid origin", { status: 403 });
    }

    return new Response(null, {
        headers: {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "86400",
        },
    });
});

// GET /auth/:app_id/login
router.get("/auth/:app_id/login", async (request: IRequest, env: Env) => {
    const { app_id } = request.params;
    const config: AppConfig | null = await env.TOKEN_STORE.get(
        `config:${app_id}`,
        "json",
    );

    if (!config) {
        return new Response("App not found", { status: 404 });
    }

    const state = nanoid();
    await env.TOKEN_STORE.put(`state:${state}`, app_id, { expirationTtl: 300 });

    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    const requestUrl = new URL(request.url);
    authUrl.searchParams.append("client_id", env.GOOGLE_CLIENT_ID);
    // Once the Google Auth flow is complete, Google will return the data to callback
    authUrl.searchParams.append(
        "redirect_uri",
        `${requestUrl.origin}/auth/${app_id}/callback`,
    );
    authUrl.searchParams.append(
        "scope",
        "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/script.projects",
    );
    authUrl.searchParams.append("response_type", "code");
    authUrl.searchParams.append("access_type", "offline");
    authUrl.searchParams.append("prompt", "consent");
    authUrl.searchParams.append("state", state);

    return Response.redirect(authUrl.toString(), 302);
});

// GET /auth/:app_id/callback
router.get("/auth/:app_id/callback", async (request: IRequest, env: Env) => {
    const { app_id } = request.params;
    const url = new URL(request.url);
    // Once Google Oauth flow is complete, Google will return the data, code and state, to callback
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (!code || !state) {
        return new Response("Missing code or state", { status: 400 });
    }

    // Compare the app id is the same as we stored to prevent CSRF attacks.
    const storedAppId = await env.TOKEN_STORE.get(`state:${state}`);
    if (storedAppId !== app_id) {
        return new Response("Invalid state", { status: 400 });
    }

    await env.TOKEN_STORE.delete(`state:${state}`);

    const config: AppConfig | null = await env.TOKEN_STORE.get(
        `config:${app_id}`,
        "json",
    );
    if (!config) {
        return new Response("App not found", { status: 404 });
    }

    const response = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            redirect_uri: `${url.origin}/auth/${app_id}/callback`,
            grant_type: "authorization_code",
            code,
        }),
    });

    const data: any = await response.json();
    if (data.error) {
        return new Response(data.error_description, { status: 400 });
    }

    const sessionId = nanoid();
    const session: Session = {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
    };
    await env.TOKEN_STORE.put(`session:${sessionId}`, JSON.stringify(session));

    const origin = request.headers.get("origin") || config.allowed_origins[0];

    // session id will be saved to FE cookie.
    const sessionCookie = cookie.serialize("session_id", sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "none", // for cross-site, or we should set "lax"
        path: "/",
    });

    return new Response(null, {
        status: 302,
        headers: {
            "Set-Cookie": sessionCookie, // set cookie to FE.
            Location: origin,
        },
    });
});

// ALL /auth/:app_id/api/*
router.all("/auth/:app_id/api/*", async (request: IRequest, env: Env) => {
    const { app_id } = request.params;
    const origin = request.headers.get("Origin");

    const config: AppConfig | null = await env.TOKEN_STORE.get(
        `config:${app_id}`,
        "json",
    );

    // A helper to create error responses with proper CORS headers
    const createCorsError = (message: string, status: number) => {
        const headers = new Headers();
        if (origin && config?.allowed_origins.includes(origin)) {
            headers.set("Access-Control-Allow-Origin", origin);
            headers.set("Access-Control-Allow-Credentials", "true");
        } else if (origin && !config) {
            // Best-effort for config loading failure, preflight should handle most cases
            headers.set("Access-Control-Allow-Origin", origin);
            headers.set("Access-Control-Allow-Credentials", "true");
        }
        return new Response(message, { status, headers });
    };

    if (!config) {
        return createCorsError("App not found", 404);
    }

    const cookies = cookie.parse(request.headers.get("Cookie") || "");
    const sessionId = cookies.session_id;

    if (!sessionId) {
        return createCorsError("Not authenticated", 401);
    }

    const session: Session | null = await env.TOKEN_STORE.get(
        `session:${sessionId}`,
        "json",
    );
    if (!session) {
        return createCorsError("Invalid session", 401);
    }

    const requestUrl = new URL(request.url);
    const gasPath = requestUrl.pathname.replace(`/auth/${app_id}/api`, "");
    const gasUrl = new URL(gasPath + requestUrl.search, config.gas_url);

    let bodyContent = null;
    if (request.method !== "GET" && request.method !== "HEAD") {
        // body is a stream, it can be read once. Transfer it to an ArrayBuffer so that it can be reused.
        bodyContent = await request.arrayBuffer();
    }

    const makeRequest = async (token: string) => {
        let finalBody: ArrayBuffer | string | null = bodyContent;
        const headers = new Headers(request.headers);
        headers.set("Content-Type", "application/json");

        if (request.method === "POST" && bodyContent) {
            try {
                // 將 ArrayBuffer 轉回 JSON 並注入 token
                const text = new TextDecoder().decode(bodyContent);
                const json = JSON.parse(text);
                json.access_token = token;
                finalBody = JSON.stringify(json);
            } catch (e) {
                console.log(e);
            }
        }
        const newReq = new Request(gasUrl.toString(), {
            method: request.method,
            headers,
            body: finalBody,
            redirect: "follow",
        });
        // console.log("make request", newReq);
        return fetch(newReq);
    };

    let response: Response | null = null;
    try {
        response = await makeRequest(session.access_token);
    } catch (error) {
        return createCorsError(`GAS failed, ${error}`, 500);
    }

    if (!response) {
        return createCorsError("response failed", 404);
    }

    const responseClone = response.clone();
    const result = await responseClone.json<GASResponse>().catch(() => null);

    if (
        result &&
        result.errorCode === "TOKEN_EXPIRED" &&
        session.refresh_token
    ) {
        console.log("token expired");

        await env.TOKEN_STORE.delete(`session:${sessionId}`);
        // Refresh the access token
        const refreshResponse = await fetch(
            "https://oauth2.googleapis.com/token",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: new URLSearchParams({
                    client_id: env.GOOGLE_CLIENT_ID,
                    client_secret: env.GOOGLE_CLIENT_SECRET,
                    refresh_token: session.refresh_token,
                    grant_type: "refresh_token",
                }),
            },
        );

        const refreshData: any = await refreshResponse.json();
        if (refreshData.access_token) {
            // Update the session with the new access token.
            session.access_token = refreshData.access_token;
            await env.TOKEN_STORE.put(
                `session:${sessionId}`,
                JSON.stringify(session),
            );
            // Make the request again with the new access token.
            response = await makeRequest(session.access_token);
        } else {
            return createCorsError("Failed to refresh token", 401);
        }
    }

    // Handle CORS for the final response
    if (origin && config.allowed_origins.includes(origin)) {
        const newHeaders = new Headers(response.headers);
        newHeaders.set("Access-Control-Allow-Origin", origin);
        newHeaders.set("Access-Control-Allow-Credentials", "true");

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders,
        });
    }

    return response;
});

// GET /auth/:app_id/logout
router.get("/auth/:app_id/logout", async (request: IRequest, env: Env) => {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "";
    const cookies = cookie.parse(request.headers.get("Cookie") || "");
    const sessionId = cookies.session_id;

    if (sessionId) {
        await env.TOKEN_STORE.delete(`session:${sessionId}`);
    }

    const sessionCookie = cookie.serialize("session_id", "", {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/",
        expires: new Date(0),
    });

    return new Response(null, {
        status: 302,
        headers: {
            "Set-Cookie": sessionCookie, // Clear FE cookie.
            Location: redirectTo,
        },
    });
});

// GET /test/config/:app_id
router.get("/test/config/:app_id", async (request: IRequest, env: Env) => {
    const origin = request.headers.get("Origin");
    if (!origin) {
        return new Response("Missing Origin header", { status: 400 });
    }
    const { app_id } = request.params;
    const config: AppConfig | null = await env.TOKEN_STORE.get(
        `config:${app_id}`,
        "json",
    );

    if (!config) {
        return new Response("App not found", { status: 404 });
    }

    return new Response(JSON.stringify(config, null, 2), {
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": origin,
        },
    });
});

// GET /test/session
router.get("/test/session", async (request: IRequest, env: Env) => {
    const cookies = cookie.parse(request.headers.get("Cookie") || "");
    const sessionId = cookies.session_id;

    if (!sessionId) {
        return new Response("Not authenticated", { status: 401 });
    }

    const session: Session | null = await env.TOKEN_STORE.get(
        `session:${sessionId}`,
        "json",
    );
    if (!session) {
        return new Response("Invalid session", { status: 401 });
    }

    return new Response(JSON.stringify(session, null, 2), {
        headers: {
            "Content-Type": "application/json",
        },
    });
});

router.all("*", () => new Response("Not Found.", { status: 404 }));

export default {
    ...router,
};
