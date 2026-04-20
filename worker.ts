/// <reference types="@cloudflare/workers-types" />
/**
 * lthm-nav — Cloudflare Worker
 *
 * Secrets (set via wrangler secret put):
 *   GITHUB_CLIENT_ID      GitHub OAuth App client ID
 *   GITHUB_CLIENT_SECRET  GitHub OAuth App secret
 *   SESSION_SECRET        random 64-char hex string
 *   ALLOWED_GITHUB_USERS  comma-separated GitHub logins, e.g. "louietien"
 *
 * Routes:
 *   GET  /auth/github           initiate GitHub OAuth flow
 *   GET  /auth/github/callback  OAuth callback
 *   POST /logout                clear session
 *   GET  /*                     static assets (requires auth)
 */

export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  SESSION_SECRET: string;
  ALLOWED_GITHUB_USERS: string;
  BASE_URL: string;
  ASSETS: Fetcher;
}

const SESSION_COOKIE = "nav_session";
const SESSION_MAX_AGE_S = 43_200; // 12 hours
const OAUTH_STATE_COOKIE = "gh_oauth_state";
const OAUTH_STATE_MAX_AGE_S = 300;

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (url.pathname === "/auth/github" && method === "GET") {
      return handleGitHubAuth(request, env);
    }

    if (url.pathname === "/auth/github/callback" && method === "GET") {
      return handleGitHubCallback(request, env);
    }

    if (url.pathname === "/logout" && method === "POST") {
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/auth/github",
          "Set-Cookie": cookieHeader(SESSION_COOKIE, "", { maxAge: 0 }),
        },
      });
    }

    const sessionToken = getCookie(request, SESSION_COOKIE);
    const authed =
      !!sessionToken &&
      (await verifySessionToken(env.SESSION_SECRET, sessionToken, SESSION_MAX_AGE_S * 1000));

    if (!authed) {
      return Response.redirect(new URL("/auth/github", url).toString(), 302);
    }

    const assetReq =
      url.pathname === "/"
        ? new Request(new URL("/index.html", url).toString(), request)
        : request;

    const assetRes = await env.ASSETS.fetch(assetReq);
    const htmlRes =
      assetRes.status === 404
        ? await env.ASSETS.fetch(new Request(new URL("/index.html", url).toString()))
        : assetRes;

    const contentType = htmlRes.headers.get("Content-Type") ?? "";
    if (contentType.includes("text/html")) {
      const body = await htmlRes.text();
      return new Response(injectLogoutButton(body), {
        status: htmlRes.status,
        headers: htmlRes.headers,
      });
    }

    return htmlRes;
  },
};

// ─── GitHub OAuth ─────────────────────────────────────────────────────────────

async function handleGitHubAuth(request: Request, env: Env): Promise<Response> {
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: new URL("/auth/github/callback", env.BASE_URL).toString(),
    scope: "read:user",
    state,
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${GITHUB_AUTHORIZE_URL}?${params}`,
      "Set-Cookie": cookieHeader(OAUTH_STATE_COOKIE, state, {
        maxAge: OAUTH_STATE_MAX_AGE_S,
        httpOnly: true,
      }),
    },
  });
}

async function handleGitHubCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const storedState = getCookie(request, OAUTH_STATE_COOKIE);

  if (!code || !state || !storedState || state !== storedState) {
    return errorPage("Invalid or expired OAuth state. <a href='/auth/github'>Try again</a>.");
  }

  const tokenRes = await fetch(GITHUB_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: new URL("/auth/github/callback", env.BASE_URL).toString(),
    }),
  });

  if (!tokenRes.ok) {
    return errorPage("GitHub token exchange failed. <a href='/auth/github'>Try again</a>.");
  }

  const tokenData = (await tokenRes.json()) as Record<string, unknown>;
  const accessToken = tokenData.access_token as string | undefined;
  if (!accessToken) {
    return errorPage("No access token returned. <a href='/auth/github'>Try again</a>.");
  }

  const userRes = await fetch(GITHUB_USER_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "lthm-nav",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!userRes.ok) {
    return errorPage("Failed to fetch GitHub user. <a href='/auth/github'>Try again</a>.");
  }

  const user = (await userRes.json()) as Record<string, unknown>;
  const login = user.login as string | undefined;
  if (!login) {
    return errorPage("No GitHub login returned. <a href='/auth/github'>Try again</a>.");
  }

  const allowed = (env.ALLOWED_GITHUB_USERS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  if (allowed.length > 0 && !allowed.includes(login.toLowerCase())) {
    return errorPage(`GitHub user <strong>${login}</strong> is not allowed.`);
  }

  const token = await createSessionToken(env.SESSION_SECRET, login);

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": cookieHeader(SESSION_COOKIE, token, {
        maxAge: SESSION_MAX_AGE_S,
        httpOnly: true,
        sameSite: "Lax",
      }),
    },
  });
}

// ─── Session crypto ───────────────────────────────────────────────────────────

async function hmac(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createSessionToken(secret: string, login: string): Promise<string> {
  const payload = `${login}:${Date.now()}`;
  const sig = await hmac(secret, payload);
  return btoa(`${payload}:${sig}`);
}

async function verifySessionToken(secret: string, token: string, maxAgeMs: number): Promise<boolean> {
  try {
    const decoded = atob(token);
    const lastColon = decoded.lastIndexOf(":");
    const payload = decoded.slice(0, lastColon);
    const sig = decoded.slice(lastColon + 1);
    const parts = payload.split(":");
    const ts = parseInt(parts[parts.length - 1], 10);
    if (isNaN(ts) || Date.now() - ts > maxAgeMs) return false;
    const expected = await hmac(secret, payload);
    return expected === sig;
  } catch {
    return false;
  }
}

// ─── Cookie helpers ───────────────────────────────────────────────────────────

function cookieHeader(
  name: string,
  value: string,
  opts: { maxAge?: number; httpOnly?: boolean; sameSite?: string } = {},
): string {
  const parts = [`${name}=${value}`, "Path=/"];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  parts.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  parts.push("Secure");
  return parts.join("; ");
}

function getCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("Cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k?.trim() === name) return v.join("=");
  }
  return undefined;
}

// ─── UI helpers ───────────────────────────────────────────────────────────────

function injectLogoutButton(html: string): string {
  return html.replace(
    '<div class="footer">',
    `<div class="footer">
      <form method="POST" action="/logout" style="margin:0">
        <button type="submit" class="theme-toggle">Sign out</button>
      </form>`,
  );
}

function errorPage(message: string): Response {
  return new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Auth Error — nav.lthm.dk</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"DM Sans",sans-serif;display:flex;
  align-items:center;justify-content:center;min-height:100vh;margin:0;
  background:#f4efe6;color:#1a1714}
p{font-size:0.95rem;text-align:center}
a{color:#bf4220}
</style></head>
<body><p>${message}</p></body></html>`,
    { status: 403, headers: { "Content-Type": "text/html;charset=utf-8" } },
  );
}
