// The demo's only import of the nsh-auth package: config, the auth instance and
// the surface glue the package cannot know about. If the package's contract
// drifts from the demo, the type errors land here alone.
import { host, signal } from "nsh";
import {
  createAuth,
  type Auth,
  type AuthStatus,
  type Session,
  type UserInfo,
} from "nsh-auth";
import { CLIENT_ID, MOCK_BASE_URL, REDIRECT_URI } from "./dev/fixtures";
import type { ProviderId } from "./providers";

export interface DemoAuthConfig {
  mockBaseUrl: string;
  clientId: string;
  redirectUri: string;
  /** A provider to sign in with on mount, from the host's launch arguments. */
  autoStart: ProviderId | null;
}

// The launch args name a provider by string; iOS answers with autoStart: true
// plus provider, Android with autoStart: "<id>".
function autoStartOf(autoStart: unknown, provider: unknown): ProviderId | null {
  if (typeof autoStart === "string" && autoStart) return autoStart as ProviderId;
  if (autoStart === true && typeof provider === "string" && provider) return provider as ProviderId;
  return null;
}

// Android mirrors the config in launch params (redirectUri is its manifest's
// intent filter); iOS answers auth.config with autoStart/provider and echoes
// mockBaseUrl. The call runs last, so the host's answer wins where both exist.
async function readHostOverrides(): Promise<Partial<DemoAuthConfig>> {
  const merged: Partial<DemoAuthConfig> = {};
  const raw = (host.params as Record<string, unknown>).auth;
  const params = (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, unknown> | undefined;
  if (params) {
    if (typeof params.mockBaseUrl === "string" && params.mockBaseUrl) merged.mockBaseUrl = params.mockBaseUrl;
    if (typeof params.redirectUri === "string" && params.redirectUri) merged.redirectUri = params.redirectUri;
    const start = autoStartOf(params.autoStart, params.provider);
    if (start) merged.autoStart = start;
  }
  if (host.available()) {
    try {
      const answer = (await host.call("auth.config", { mockBaseUrl: merged.mockBaseUrl ?? undefined })) as
        | Record<string, unknown>
        | null;
      if (answer) {
        if (typeof answer.mockBaseUrl === "string" && answer.mockBaseUrl) merged.mockBaseUrl = answer.mockBaseUrl;
        const start = autoStartOf(answer.autoStart, answer.provider);
        if (start) merged.autoStart = start;
      }
    } catch {
      // no auth.config handler: the params mirror (or the defaults) stand
    }
  }
  return merged;
}

const instance = signal<Auth | null>(null);
const config = signal<DemoAuthConfig | null>(null);

/** True once createAuth ran with the host's config (tracked where read). */
export const authReady = (): boolean => instance() !== null;

function requireAuth(): Auth {
  const current = instance();
  if (!current) throw new Error("auth is not ready");
  return current;
}

/** The demo's config; valid only while authReady. */
export const authConfig = (): DemoAuthConfig => {
  const current = config();
  if (!current) throw new Error("auth is not ready");
  return current;
};

/**
 * Reads the host's config, then builds the auth instance. The config must be
 * final first: createAuth closes over mockBaseUrl and the redirect URI.
 */
export async function initAuth(): Promise<void> {
  if (instance()) return;
  const overrides = await readHostOverrides();
  config.set({
    mockBaseUrl: overrides.mockBaseUrl ?? MOCK_BASE_URL,
    clientId: overrides.clientId ?? CLIENT_ID,
    redirectUri: overrides.redirectUri ?? REDIRECT_URI,
    autoStart: overrides.autoStart ?? null,
  });
  instance.set(
    createAuth({
      clientId: authConfig().clientId,
      redirectUri: authConfig().redirectUri,
      mockBaseUrl: authConfig().mockBaseUrl,
    }),
  );
}

export const session = (): Session | null => requireAuth().session();
export const user = (): UserInfo | null => requireAuth().user();
export const status = (): AuthStatus => requireAuth().status();
export const authError = (): { code: string; message?: string } | null => requireAuth().error();
export const signIn = (provider: ProviderId): Promise<void> => requireAuth().signIn(provider);
export const handleRedirect = (url: string): Promise<void> => requireAuth().handleRedirect(url);
export const refreshSession = (): Promise<void> => requireAuth().refresh();
export const signOut = (): Promise<void> => requireAuth().signOut();

/** True while a sign-in is on its way or trading the code (tracked where read). */
export const authBusy = (): boolean => status() === "authorizing" || status() === "exchanging";

/** The id_token's payload for the readout. The package did the signature checks. */
export function idTokenClaims(): Record<string, unknown> | null {
  const token = session()?.idToken;
  const payload = typeof token === "string" ? token.split(".")[1] : undefined;
  if (!payload) return null;
  try {
    const json = Buffer.from(payload, "base64").toString("utf8");
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** One read of the session for the tokens readout. */
export function claimInfo(): {
  claims: Record<string, unknown> | null;
  accessTokenTail: string | null;
  refreshTokenPresent: boolean;
} {
  const current = session();
  return {
    claims: idTokenClaims(),
    accessTokenTail: current?.accessToken ? current.accessToken.slice(-4) : null,
    refreshTokenPresent: Boolean(current?.refreshToken),
  };
}
