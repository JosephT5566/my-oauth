import { IttyRouter, IRequest } from 'itty-router';

// IMPORTANT: REPLACE THE PLACEHOLDER VALUES BELOW WITH YOUR GOOGLE OAUTH CREDENTIALS
const GOOGLE_CLIENT_ID = 'YOUR_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = 'YOUR_CLIENT_SECRET';
const REDIRECT_URI = 'http://localhost:8787/callback';

const router = IttyRouter();

router.get('/', () => new Response('Hello World!'));

router.get('/auth', () => {
	const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
	url.searchParams.append('client_id', GOOGLE_CLIENT_ID);
	url.searchParams.append('redirect_uri', REDIRECT_URI);
	url.searchParams.append('scope', 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile');
	url.searchParams.append('response_type', 'code');
	url.searchParams.append('access_type', 'offline');
	url.searchParams.append('prompt', 'consent');
	return Response.redirect(url.toString(), 302);
});

router.get('/callback', async (request: IRequest, env: Env) => {
	const url = new URL(request.url);
	const code = url.searchParams.get('code');

	const response = await fetch('https://oauth2.googleapis.com/token', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: new URLSearchParams({
			client_id: GOOGLE_CLIENT_ID,
			client_secret: GOOGLE_CLIENT_SECRET,
			redirect_uri: REDIRECT_URI,
			grant_type: 'authorization_code',
			code,
		}),
	});

	const data: any = await response.json();
	await env.TOKEN_STORE.put('access_token', data.access_token);
	if (data.refresh_token) {
		await env.TOKEN_STORE.put('refresh_token', data.refresh_token);
	}

	return new Response(JSON.stringify(data), {
		headers: {
			'Content-Type': 'application/json',
		},
	});
});

router.get('/proxy', async (request: IRequest, env: Env) => {
	let accessToken = await env.TOKEN_STORE.get('access_token');
	if (!accessToken) {
		return new Response('Not authenticated', { status: 401 });
	}

	const url = 'https://www.googleapis.com/oauth2/v2/userinfo';
	const headers = new Headers(request.headers);
	headers.set('Authorization', `Bearer ${accessToken}`);

	let response = await fetch(url, {
		method: request.method,
		headers,
		body: request.body,
	});

	if (response.status === 401) {
		const refreshToken = await env.TOKEN_STORE.get('refresh_token');
		if (!refreshToken) {
			return new Response('Refresh token not found', { status: 401 });
		}

		const refreshResponse = await fetch('https://oauth2.googleapis.com/token', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				client_id: GOOGLE_CLIENT_ID,
				client_secret: GOOGLE_CLIENT_SECRET,
				refresh_token: refreshToken,
				grant_type: 'refresh_token',
			}),
		});

		const refreshData: any = await refreshResponse.json();
		if (refreshData.access_token) {
			accessToken = refreshData.access_token;
			await env.TOKEN_STORE.put('access_token', accessToken);
			headers.set('Authorization', `Bearer ${accessToken}`);
			response = await fetch(url, {
				method: request.method,
				headers,
				body: request.body,
			});
		} else {
			return new Response('Failed to refresh token', { status: 401 });
		}
	}

	return response;
});

router.all('*', () => new Response('Not Found.', { status: 404 }));

export default {
	fetch: (request: IRequest, env: Env, ctx: ExecutionContext) => router.handle(request, env, ctx),
};
