import { AuthError, type AuthErrorCode } from "./errors";
import type { ProviderConfig } from "./providers";

export interface TokenResponse {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
  scope: string;
}

export interface ExchangeOptions {
  config: ProviderConfig;
  clientId: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
  brokerUrl?: string;
  nowMs: () => number;
  fallbackScope: string;
}

export interface RefreshOptions {
  config: ProviderConfig;
  clientId: string;
  refreshToken: string;
  brokerUrl?: string;
  nowMs: () => number;
  fallbackScope: string;
}

const DEFAULT_EXPIRES_IN = 3600;

export async function exchangeCode(options: ExchangeOptions): Promise<TokenResponse> {
  const provider = options.config;
  if (provider.needsBroker) {
    if (!options.brokerUrl) {
      throw new AuthError("broker_error", `${provider.id} needs brokerUrl: its client secret must never live in the app`);
    }
    return fromBroker(
      await postJson(`${options.brokerUrl}/token`, {
        provider: provider.id,
        code: options.code,
        // PKCE-less providers (Apple) take no verifier through the broker.
        ...(provider.usePkce ? { codeVerifier: options.codeVerifier } : {}),
        redirectUri: options.redirectUri,
      }),
      options.nowMs,
      options.fallbackScope,
    );
  }
  if (!provider.tokenUrl) throw new AuthError("unknown", `${provider.id} has no token endpoint`);
  if (provider.tokenMethod === "GET") {
    // Facebook's OIDC flow: the code exchange is a GET with the verifier in the query.
    const url = new URL(provider.tokenUrl);
    url.searchParams.set("client_id", options.clientId);
    url.searchParams.set("redirect_uri", options.redirectUri);
    url.searchParams.set("code", options.code);
    if (provider.usePkce) url.searchParams.set("code_verifier", options.codeVerifier);
    return fromDirect(await getJson(url.toString()), options.nowMs, options.fallbackScope);
  }
  const form = new URLSearchParams();
  form.set("grant_type", "authorization_code");
  form.set("code", options.code);
  form.set("redirect_uri", options.redirectUri);
  form.set("client_id", options.clientId);
  if (provider.usePkce) form.set("code_verifier", options.codeVerifier);
  return fromDirect(await postForm(provider.tokenUrl, form), options.nowMs, options.fallbackScope);
}

export async function refreshTokens(options: RefreshOptions): Promise<TokenResponse> {
  const provider = options.config;
  if (provider.needsBroker) {
    if (!options.brokerUrl) {
      throw new AuthError("broker_error", `${provider.id} needs brokerUrl: its client secret must never live in the app`);
    }
    return fromBroker(
      await postJson(`${options.brokerUrl}/token`, { provider: provider.id, refreshToken: options.refreshToken }),
      options.nowMs,
      options.fallbackScope,
    );
  }
  if (!provider.tokenUrl) throw new AuthError("unknown", `${provider.id} has no token endpoint`);
  const form = new URLSearchParams();
  form.set("grant_type", "refresh_token");
  form.set("refresh_token", options.refreshToken);
  form.set("client_id", options.clientId);
  return fromDirect(await postForm(provider.tokenUrl, form), options.nowMs, options.fallbackScope);
}

export interface RevokeOptions {
  config: ProviderConfig;
  brokerUrl?: string;
  token: string;
}

export async function revokeToken(options: RevokeOptions): Promise<void> {
  const provider = options.config;
  if (provider.needsBroker) {
    if (!options.brokerUrl) {
      throw new AuthError("broker_error", `${provider.id} needs brokerUrl: its client secret must never live in the app`);
    }
    await postJson(`${options.brokerUrl}/revoke`, { provider: provider.id, token: options.token });
    return;
  }
  if (!provider.revokeUrl) return;
  const form = new URLSearchParams();
  form.set("token", options.token);
  let response: Response;
  try {
    response = await fetch(provider.revokeUrl, {
      method: provider.revokeMethod ?? "POST",
      body: form.toString(),
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
  } catch (error) {
    throw new AuthError("network", `revoke request failed: ${String(error)}`);
  }
  if (!response.ok) throw new AuthError("unknown", `revoke failed with status ${response.status}`);
}

function fromDirect(body: Record<string, unknown>, nowMs: () => number, fallbackScope: string): TokenResponse {
  if (typeof body.access_token !== "string") throw tokenError(body);
  const expiresIn = typeof body.expires_in === "number" ? body.expires_in : DEFAULT_EXPIRES_IN;
  return {
    accessToken: body.access_token,
    refreshToken: typeof body.refresh_token === "string" ? body.refresh_token : undefined,
    idToken: typeof body.id_token === "string" ? body.id_token : undefined,
    expiresAt: nowMs() + expiresIn * 1000,
    scope: typeof body.scope === "string" && body.scope ? body.scope : fallbackScope,
  };
}

function fromBroker(body: Record<string, unknown>, nowMs: () => number, fallbackScope: string): TokenResponse {
  if (typeof body.accessToken !== "string") {
    throw new AuthError("broker_error", "the broker response has no accessToken");
  }
  const expiresIn = typeof body.expiresIn === "number" ? body.expiresIn : DEFAULT_EXPIRES_IN;
  return {
    accessToken: body.accessToken,
    refreshToken: typeof body.refreshToken === "string" ? body.refreshToken : undefined,
    idToken: typeof body.idToken === "string" ? body.idToken : undefined,
    expiresAt: nowMs() + expiresIn * 1000,
    scope: typeof body.scope === "string" && body.scope ? body.scope : fallbackScope,
  };
}

function tokenError(body: Record<string, unknown>): AuthError {
  const error = typeof body.error === "string" ? body.error : "unknown";
  const description = typeof body.error_description === "string" ? body.error_description : "";
  if (error === "invalid_grant" && /expired/i.test(description)) {
    return new AuthError("expired_code", description || error);
  }
  if (error === "invalid_grant") return new AuthError("invalid_grant", description || error);
  if (error === "access_denied") return new AuthError("access_denied", description || error);
  return new AuthError("unknown", description || error);
}

async function postForm(url: string, form: URLSearchParams): Promise<Record<string, unknown>> {
  const response = await send(url, {
    method: "POST",
    body: form.toString(),
    headers: { "content-type": "application/x-www-form-urlencoded" },
  });
  return readJson(response);
}

async function postJson(url: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = await send(url, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
  });
  const body = await readBody(response, "broker_error");
  if (!response.ok) throw new AuthError("broker_error", `broker returned status ${response.status}`);
  return body;
}

async function getJson(url: string): Promise<Record<string, unknown>> {
  const response = await send(url, { method: "GET" });
  return readJson(response);
}

async function send(url: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch (error) {
    throw new AuthError("network", `request failed: ${String(error)}`);
  }
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  return readBody(response, "unknown");
}

// A 204 carries no body; anything else unreadable counts against the caller's code.
async function readBody(response: Response, malformed: AuthErrorCode): Promise<Record<string, unknown>> {
  if (response.status === 204) return {};
  try {
    return (await response.json()) as Record<string, unknown>;
  } catch {
    throw new AuthError(malformed, `response from ${response.url} is not JSON`);
  }
}
