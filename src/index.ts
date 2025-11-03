import { Buffer } from 'node:buffer';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

interface Env {
	GITHUB_APP_CLIENT_ID: string;
	GITHUB_APP_CLIENT_SECRET: string;
}

const GITHUB_OAUTH_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_OAUTH_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_AGENT = 'ironshard-decap-oauth-proxy';
const STATE_TTL_SECONDS = 600;

const base64UrlEncode = (input: Buffer) => input.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const base64UrlDecode = (input: string) => {
	const padLength = (4 - (input.length % 4)) % 4;
	const padded = input + '='.repeat(padLength);
	return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
};

const signStatePayload = (encodedPayload: string, env: Env) =>
	createHmac('sha256', env.GITHUB_APP_CLIENT_SECRET).update(encodedPayload).digest('hex');

const createState = (env: Env) => {
	const payload = {
		nonce: randomBytes(16).toString('hex'),
		exp: Math.floor(Date.now() / 1000) + STATE_TTL_SECONDS,
	};
	const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
	const signature = signStatePayload(encodedPayload, env);
	return `${encodedPayload}.${signature}`;
};

const verifyState = (state: string, env: Env) => {
	const [encodedPayload, signature] = state.split('.');
	if (!encodedPayload || !signature) {
		throw new Error('State is malformed');
	}
	const expectedSignature = signStatePayload(encodedPayload, env);
	const providedBuffer = Buffer.from(signature, 'hex');
	const expectedBuffer = Buffer.from(expectedSignature, 'hex');
	if (
		providedBuffer.length !== expectedBuffer.length ||
		!timingSafeEqual(providedBuffer, expectedBuffer)
	) {
		throw new Error('State signature mismatch');
	}
	const payloadJson = base64UrlDecode(encodedPayload).toString('utf8');
	const payload = JSON.parse(payloadJson) as { exp?: number };
	if (!payload.exp || typeof payload.exp !== 'number') {
		throw new Error('State payload missing expiry');
	}
	if (payload.exp < Math.floor(Date.now() / 1000)) {
		throw new Error('State expired');
	}
};

const exchangeCodeForUserToken = async (env: Env, code: string, redirectUrl: string) => {
	const response = await fetch(GITHUB_OAUTH_TOKEN_URL, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			'User-Agent': USER_AGENT,
		},
		body: JSON.stringify({
			client_id: env.GITHUB_APP_CLIENT_ID,
			client_secret: env.GITHUB_APP_CLIENT_SECRET,
			code,
			redirect_uri: redirectUrl,
		}),
	});

	const json = (await response.json()) as {
		access_token?: string;
		error?: string;
		error_description?: string;
	};

	if (!response.ok || !json.access_token) {
		const detail = json.error_description || json.error || `status ${response.status}`;
		throw new Error(`Failed to exchange code for user token: ${detail}`);
	}

	return json.access_token;
};

const handleAuth = (url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

	const state = createState(env);
	const redirectUrl = `https://${url.hostname}/callback?provider=github`;
	const authorizeUrl = `${GITHUB_OAUTH_AUTHORIZE_URL}?client_id=${env.GITHUB_APP_CLIENT_ID}&redirect_uri=${encodeURIComponent(
		redirectUrl
	)}&state=${state}&allow_signup=false&scope=read:user`;

	return new Response(null, {
		headers: {
			location: authorizeUrl,
		},
		status: 301,
	});
};

const callbackScriptResponse = (status: string, token: string) => {
	return new Response(
		`
<html>
<head>
	<script>
		const receiveMessage = (message) => {
			window.opener.postMessage(
				'authorization:github:${status}:${JSON.stringify({ token })}',
				'*'
			);
			window.removeEventListener("message", receiveMessage, false);
		}
		window.addEventListener("message", receiveMessage, false);
		window.opener.postMessage("authorizing:github", "*");
	</script>
	<body>
		<p>Authorizing Decap...</p>
	</body>
</head>
</html>
`,
		{ headers: { 'Content-Type': 'text/html' } }
	);
};

const handleCallback = async (url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

	const stateParam = url.searchParams.get('state');
	if (!stateParam) {
		return callbackScriptResponse('error', 'Missing state parameter');
	}

	try {
		verifyState(stateParam, env);
		const redirectUrl = `https://${url.hostname}/callback?provider=github`;
		const code = url.searchParams.get('code');
		if (!code) {
			return callbackScriptResponse('error', 'Missing code');
		}

		const userToken = await exchangeCodeForUserToken(env, code, redirectUrl);
		return callbackScriptResponse('success', userToken);
	} catch (error) {
		const message = error instanceof Error ? error.message : 'Failed to retrieve access token';
		return callbackScriptResponse('error', message);
	}
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === '/auth') {
			return handleAuth(url, env);
		}
		if (url.pathname === '/callback') {
			return handleCallback(url, env);
		}
		return new Response('Hello 👋');
	},
};
