import { Buffer } from 'node:buffer';
import { createSign, randomBytes } from 'node:crypto';

interface Env {
	GITHUB_APP_ID: string;
	GITHUB_APP_SLUG: string;
	GITHUB_APP_PRIVATE_KEY: string;
	GITHUB_APP_CLIENT_ID: string;
	GITHUB_APP_CLIENT_SECRET: string;
	GITHUB_APP_REPOSITORY: string;
}

const GITHUB_API = 'https://api.github.com';
const GITHUB_INSTALLATION_URL = 'https://github.com/apps';
const GITHUB_OAUTH_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_OAUTH_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_AGENT = 'ironshard-decap-oauth-proxy';
const STATE_COOKIE = 'github_app_state';
const STATE_COOKIE_ATTRS = '; Path=/; HttpOnly; Secure; SameSite=Lax';

const stateCookieValue = (state: string) => `${STATE_COOKIE}=${state}; Max-Age=600${STATE_COOKIE_ATTRS}`;
const clearStateCookie = `${STATE_COOKIE}=; Max-Age=0${STATE_COOKIE_ATTRS}`;

const parseRepository = (fullName: string) => {
	const [owner, repo] = fullName.split('/');
	if (!owner || !repo) {
		throw new Error('GITHUB_APP_REPOSITORY must be in the form "owner/repo"');
	}
	return { owner, repo };
};

const normalizePrivateKey = (rawKey: string) => rawKey.replace(/\\n/g, '\n');

const base64Url = (input: Buffer) => input.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const createAppJWT = (env: Env) => {
	const now = Math.floor(Date.now() / 1000);
	const header = base64Url(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
	const payload = base64Url(
		Buffer.from(
			JSON.stringify({
				iat: now - 60,
				exp: now + 60 * 9,
				iss: env.GITHUB_APP_ID,
			})
		)
	);
	const data = `${header}.${payload}`;
	const signer = createSign('RSA-SHA256');
	signer.update(data);
	signer.end();
	const privateKey = normalizePrivateKey(env.GITHUB_APP_PRIVATE_KEY);
	const signature = signer.sign(privateKey);
	return `${data}.${base64Url(signature)}`;
};

const requestInstallationToken = async (env: Env, installationId: string, repo: string) => {
	const jwt = createAppJWT(env);
	const response = await fetch(`${GITHUB_API}/app/installations/${installationId}/access_tokens`, {
		method: 'POST',
		headers: {
			Accept: 'application/vnd.github+json',
			Authorization: `Bearer ${jwt}`,
			'Content-Type': 'application/json',
			'User-Agent': USER_AGENT,
		},
		body: JSON.stringify({ repositories: [repo] }),
	});

	if (!response.ok) {
		const body = await response.text();
		throw new Error(`Failed to request installation token: ${response.status} ${body}`);
	}

	const json = (await response.json()) as { token: string };
	return json.token;
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

const findInstallationId = async (env: Env, userToken: string, owner: string, fullRepoName: string) => {
	const installationsResponse = await fetch(`${GITHUB_API}/user/installations`, {
		headers: {
			Accept: 'application/vnd.github+json',
			Authorization: `Bearer ${userToken}`,
			'User-Agent': USER_AGENT,
		},
	});

	if (!installationsResponse.ok) {
		const body = await installationsResponse.text();
		throw new Error(`Failed to list installations: ${installationsResponse.status} ${body}`);
	}

	const data = (await installationsResponse.json()) as {
		installations?: Array<{
			id: number;
			app_id: number;
			account?: { login?: string };
		}>;
	};

	const targetOwner = owner.toLowerCase();
	const targetFullName = fullRepoName.toLowerCase();
	const installations = data.installations ?? [];

	for (const installation of installations) {
		if (Number(installation.app_id) !== Number(env.GITHUB_APP_ID)) {
			continue;
		}
		const accountLogin = installation.account?.login?.toLowerCase();
		if (accountLogin !== targetOwner) {
			continue;
		}

		const repositoriesResponse = await fetch(
			`${GITHUB_API}/user/installations/${installation.id}/repositories`,
			{
				headers: {
					Accept: 'application/vnd.github+json',
					Authorization: `Bearer ${userToken}`,
					'User-Agent': USER_AGENT,
				},
			}
		);

		if (!repositoriesResponse.ok) {
			const body = await repositoriesResponse.text();
			throw new Error(`Failed to list installation repositories: ${repositoriesResponse.status} ${body}`);
		}

		const repositoriesData = (await repositoriesResponse.json()) as {
			repositories?: Array<{ full_name: string }>;
		};

		const match = (repositoriesData.repositories ?? []).find(
			(repository) => repository.full_name.toLowerCase() === targetFullName
		);
		if (match) {
			return installation.id.toString();
		}
	}

	throw new Error(
		`GitHub App is not installed for the required repository. Install it at ${GITHUB_INSTALLATION_URL}/${env.GITHUB_APP_SLUG}/installations/new`
	);
};

const handleAuth = (url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

	const state = randomBytes(4).toString('hex');
	const redirectUrl = `https://${url.hostname}/callback?provider=github`;
	const authorizeUrl = `${GITHUB_OAUTH_AUTHORIZE_URL}?client_id=${env.GITHUB_APP_CLIENT_ID}&redirect_uri=${encodeURIComponent(
		redirectUrl
	)}&state=${state}&allow_signup=false&scope=read:user`;

	return new Response(null, {
		headers: {
			location: authorizeUrl,
			'Set-Cookie': stateCookieValue(state),
		},
		status: 301,
	});
};

const callbackScriptResponse = (status: string, token: string, extraHeaders: HeadersInit = {}) => {
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
		{ headers: { 'Content-Type': 'text/html', ...extraHeaders } }
	);
};

const getCookie = (header: string | null, name: string) => {
	if (!header) {
		return null;
	}
	for (const cookie of header.split(';')) {
		const [key, ...rest] = cookie.trim().split('=');
		if (key === name) {
			return rest.join('=').trim();
		}
	}
	return null;
};

const handleCallback = async (request: Request, url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

	const stateParam = url.searchParams.get('state');
	const storedState = getCookie(request.headers.get('Cookie'), STATE_COOKIE);
	if (!stateParam || !storedState || storedState !== stateParam) {
		return callbackScriptResponse('error', 'State verification failed', {
			'Set-Cookie': clearStateCookie,
		});
	}

	try {
		const redirectUrl = `https://${url.hostname}/callback?provider=github`;
		const code = url.searchParams.get('code');
		if (!code) {
			return callbackScriptResponse('error', 'Missing code', {
				'Set-Cookie': clearStateCookie,
			});
		}

		const { owner, repo } = parseRepository(env.GITHUB_APP_REPOSITORY);
		const userToken = await exchangeCodeForUserToken(env, code, redirectUrl);
		const installationId =
			url.searchParams.get('installation_id') ?? (await findInstallationId(env, userToken, owner, env.GITHUB_APP_REPOSITORY));
		const accessToken = await requestInstallationToken(env, installationId, repo);
		return callbackScriptResponse('success', accessToken, {
			'Set-Cookie': clearStateCookie,
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : 'Failed to retrieve access token';
		return callbackScriptResponse('error', message, {
			'Set-Cookie': clearStateCookie,
		});
	}
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === '/auth') {
			return handleAuth(url, env);
		}
		if (url.pathname === '/callback') {
			return handleCallback(request, url, env);
		}
		return new Response('Hello 👋');
	},
};
