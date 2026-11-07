import { openUrl, signal } from "nsh";
import { buildAuthorizeUrl } from "./authorize";
import { parseCallback } from "./callback";
import { AuthError } from "./errors";
import { hostAuthorize, hostAvailable, HostStore } from "./host";
import { verifyIdToken } from "./jwks";
import { codeChallengeS256, createCodeVerifier, createNonce, createState } from "./pkce";
import { DEFAULT_MOCK_BASE_URL, providerConfig, type ProviderId } from "./providers";
import { MemoryStore } from "./store";
import type { Auth, AuthConfig, AuthStatus, Session, SessionStore, UserInfo } from "./types";
import { exchangeCode, refreshTokens, revokeToken } from "./tokens";
import { fetchUserInfo, mapUserInfo } from "./userinfo";

const SESSION_KEY = "nsh-auth:session";

interface Pending {
  provider: ProviderId;
  state: string;
  nonce: string;
  verifier: string;
  scopes: string;
  resolve: () => void;
  reject: (error: AuthError) => void;
}

export function createAuth(config: AuthConfig): Auth {
  const clock = config.clock ?? { nowMs: () => Date.now() };
  const mockBaseUrl = config.mockBaseUrl ?? DEFAULT_MOCK_BASE_URL;
  const mode = config.storage ?? "auto";
  const store: SessionStore =
    mode === "memory"
      ? new MemoryStore()
      : mode === "host"
        ? new HostStore(SESSION_KEY)
        : hostAvailable()
          ? new HostStore(SESSION_KEY)
          : new MemoryStore();

  const session = signal<Session | null>(null);
  const user = signal<UserInfo | null>(null);
  const status = signal<AuthStatus>("idle");
  const error = signal<AuthError | null>(null);

  let pending: Pending | null = null;
  let refreshing: Promise<void> | null = null;
  // Bumped by signIn and signOut: work from an older epoch is abandoned.
  let generation = 0;

  // Restore once at start; a failure here stays quiet because the next store
  // call reports it and a broken store at boot must not stop the app.
  void (async () => {
    try {
      const stored = await store.load();
      if (stored && stored.expiresAt > clock.nowMs()) {
        session.set(stored);
        status.set("authenticated");
      } else if (stored) {
        await store.clear();
      }
    } catch {
      // reported by the next sign-in, refresh or sign-out instead
    }
  })();

  function redirectScheme(): string {
    return config.redirectUri.slice(0, config.redirectUri.indexOf("://"));
  }

  async function signIn(provider: ProviderId): Promise<void> {
    const providerInfo = providerConfig(provider, mockBaseUrl);
    const verifier = createCodeVerifier();
    const state = createState();
    const nonce = createNonce();
    const scopes = config.scopes?.[provider] ?? providerInfo.defaultScopes;
    const url = buildAuthorizeUrl({
      provider: providerInfo,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      scopes,
      codeChallenge: providerInfo.usePkce ? await codeChallengeS256(verifier) : undefined,
      state,
      nonce: providerInfo.wantsNonce ? nonce : undefined,
    });
    config.onAuthorizeUrl?.(url);
    error.set(null);
    status.set("authorizing");
    const previous = pending;
    pending = null;
    generation += 1;
    previous?.reject(new AuthError("unknown", "superseded by a new sign-in"));
    return new Promise<void>((resolve, reject) => {
      pending = { provider, state, nonce, verifier, scopes: scopes.join(" "), resolve, reject };
      void launch(url);
    });
  }

  async function launch(url: string): Promise<void> {
    const waiting = pending;
    if (!waiting) return;
    try {
      if (hostAvailable()) {
        const callbackUrl = await hostAuthorize(url, redirectScheme());
        // The callback answers the flow that launched it; if a newer sign-in
        // has taken `pending`, this one's late answer is dropped, not judged.
        if (pending !== waiting) return;
        await deliverRedirect(callbackUrl);
        return;
      }
      const result = await openUrl(url);
      if (!result.opened) {
        throw new AuthError("no_launcher", `nothing opens ${redirectScheme()} URLs, so no browser can launch`);
      }
      // Without a host there is no listener and no scheme: the redirect cannot
      // arrive by itself. The flow stays `authorizing` until the app calls
      // `handleRedirect` with the callback URL the user or a page bridge pastes back.
    } catch (cause) {
      const authError = toAuthError(cause);
      if (pending === waiting) {
        pending = null;
        status.set("error");
        error.set(authError);
        waiting.reject(authError);
      }
    }
  }

  async function deliverRedirect(callbackUrl: string): Promise<void> {
    const waiting = pending;
    const epoch = generation;
    try {
      const callback = parseCallback(callbackUrl);
      // CSRF backstop: the host's intent filter is the first line, this is the
      // second. A callback with no state at all must not reach the exchange.
      if (waiting && callback.state !== waiting.state) {
        throw new AuthError("state_mismatch", "the callback carries no state, or its state does not match the one sent");
      }
      if (callback.error) throw callbackError(callback.error, callback.errorDescription);
      if (!waiting) throw new AuthError("unknown", "no sign-in is waiting for a redirect");
      if (!callback.code) throw new AuthError("unknown", "the callback carries no code");
      status.set("exchanging");
      const providerInfo = providerConfig(waiting.provider, mockBaseUrl);
      const response = await exchangeCode({
        config: providerInfo,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        code: callback.code,
        codeVerifier: waiting.verifier,
        brokerUrl: config.brokerUrl,
        nowMs: () => clock.nowMs(),
        fallbackScope: waiting.scopes,
      });
      let claims: Record<string, unknown> | null = null;
      if (response.idToken && providerInfo.jwksUrl) {
        claims = await verifyIdToken({
          idToken: response.idToken,
          jwksUrl: providerInfo.jwksUrl,
          issuer: providerInfo.issuer,
          audience: config.clientId,
          expectedNonce: providerInfo.wantsNonce ? waiting.nonce : undefined,
          nowMs: () => clock.nowMs(),
        });
      }
      const raw = providerInfo.userinfoUrl ? await fetchUserInfo(providerInfo.userinfoUrl, response.accessToken) : claims;
      if (!raw) throw new AuthError("unknown", "neither userinfo nor id-token claims came back");
      // A sign-out or a newer sign-in during the exchange owns the state now;
      // never apply this session across an epoch change.
      if (generation !== epoch) {
        throw new AuthError("unknown", "cancelled by a sign-out or a newer sign-in");
      }
      const next: Session = {
        provider: waiting.provider,
        accessToken: response.accessToken,
        refreshToken: response.refreshToken,
        idToken: response.idToken,
        expiresAt: response.expiresAt,
        scope: response.scope,
      };
      await store.save(next);
      // The save can race a sign-out's clear: re-check and drop what was written.
      if (generation !== epoch) {
        try {
          await store.clear();
        } catch {
          // the cancellation report must not be masked by a store error
        }
        throw new AuthError("unknown", "cancelled by a sign-out or a newer sign-in");
      }
      session.set(next);
      user.set(mapUserInfo(waiting.provider, raw));
      status.set("authenticated");
      error.set(null);
      pending = null;
      waiting.resolve();
    } catch (cause) {
      const authError = toAuthError(cause);
      if (generation !== epoch) {
        // The newer operation owns `pending` and the signals; settle this
        // promise only.
        if (waiting) waiting.reject(authError);
        else throw authError;
        return;
      }
      pending = null;
      status.set("error");
      error.set(authError);
      if (waiting) waiting.reject(authError);
      else throw authError;
    }
  }

  async function doRefresh(): Promise<void> {
    const epoch = generation;
    const current = session();
    if (!current?.refreshToken) {
      const authError = new AuthError("invalid_grant", "no refresh token to refresh with");
      status.set("error");
      error.set(authError);
      throw authError;
    }
    status.set("refreshing");
    error.set(null);
    try {
      const providerInfo = providerConfig(current.provider, mockBaseUrl);
      const response = await refreshTokens({
        config: providerInfo,
        clientId: config.clientId,
        refreshToken: current.refreshToken,
        brokerUrl: config.brokerUrl,
        nowMs: () => clock.nowMs(),
        fallbackScope: current.scope,
      });
      // A sign-out or a newer sign-in during the request owns the state now;
      // never apply this refresh's rotated token across an epoch change.
      if (generation !== epoch) {
        throw new AuthError("unknown", "cancelled by a sign-out or a newer sign-in");
      }
      const next: Session = {
        ...current,
        accessToken: response.accessToken,
        refreshToken: response.refreshToken ?? current.refreshToken,
        idToken: response.idToken ?? current.idToken,
        expiresAt: response.expiresAt,
        scope: response.scope,
      };
      await store.save(next);
      // The save can race a sign-out's clear: re-check and drop what was written.
      if (generation !== epoch) {
        try {
          await store.clear();
        } catch {
          // the cancellation report must not be masked by a store error
        }
        throw new AuthError("unknown", "cancelled by a sign-out or a newer sign-in");
      }
      session.set(next);
      status.set("authenticated");
    } catch (cause) {
      const authError = toAuthError(cause);
      if (generation !== epoch) {
        // The newer operation owns the signals; report only on this promise.
        throw authError;
      }
      status.set("error");
      error.set(authError);
      // A refresh token the server rejects is dead: drop the local session too.
      if (authError.code === "invalid_grant" || authError.code === "expired_code") {
        session.set(null);
        user.set(null);
        try {
          await store.clear();
        } catch {
          // the refresh failure is already reported
        }
      }
      throw authError;
    }
  }

  async function signOut(): Promise<void> {
    generation += 1;
    const current = session();
    const waiting = pending;
    pending = null;
    waiting?.reject(new AuthError("unknown", "sign-out cancelled the sign-in"));
    if (current) {
      try {
        await revokeToken({
          config: providerConfig(current.provider, mockBaseUrl),
          brokerUrl: config.brokerUrl,
          token: current.refreshToken ?? current.accessToken,
        });
      } catch {
        // Revocation is best-effort; dropping the local session is the security property.
      }
    }
    try {
      await store.clear();
    } catch (cause) {
      const authError = toAuthError(cause);
      status.set("error");
      error.set(authError);
      throw authError;
    }
    session.set(null);
    user.set(null);
    status.set("idle");
    error.set(null);
  }

  return {
    session,
    user,
    status,
    error,
    signIn,
    handleRedirect: (url: string): Promise<void> => deliverRedirect(url),
    refresh: (): Promise<void> => {
      // Single flight: parallel refreshes share the request in flight.
      refreshing ??= doRefresh().finally(() => {
        refreshing = null;
      });
      return refreshing;
    },
    signOut,
  };
}

function callbackError(error: string, description: string | null): AuthError {
  if (error === "access_denied") return new AuthError("access_denied", description ?? "the user denied the request");
  if (error === "expired_token" || error === "expired_code" || error === "authorization_expired") {
    return new AuthError("expired_code", description ?? error);
  }
  return new AuthError("unknown", description ?? error);
}

function toAuthError(cause: unknown): AuthError {
  return cause instanceof AuthError ? cause : new AuthError("unknown", cause instanceof Error ? cause.message : String(cause));
}
