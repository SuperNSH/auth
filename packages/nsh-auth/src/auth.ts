import { openUrl, signal, untracked } from "nsh";
import { buildAuthorizeUrl } from "./authorize";
import { parseCallback } from "./callback";
import { AuthError } from "./errors";
import {
  clearPendingAuthorize,
  hostAuthorize,
  hostAvailable,
  HostStore,
  loadPendingAuthorize,
  nativeSignIn,
  type NativeSignInProvider,
  type NativeSignInResult,
  type PendingAuthorize,
} from "./host";
import { verifyIdToken } from "./jwks";
import { codeChallengeS256, createCodeVerifier, createNonce, createState, sha256Hex } from "./pkce";
import { DEFAULT_MOCK_BASE_URL, providerConfig, type ProviderConfig, type ProviderId } from "./providers";
import { MemoryStore } from "./store";
import { sessionExpired, type Auth, type AuthConfig, type AuthStatus, type Session, type SessionStore, type UserInfo } from "./types";
import { exchangeCode, refreshTokens, revokeToken } from "./tokens";
import { fetchUserInfo, mapUserInfo } from "./userinfo";

const SESSION_KEY = "nsh-auth:session";

// The providers whose native SDK legs the auth.nativeSignIn channel serves.
const NATIVE_SIGN_IN_PROVIDERS: ReadonlySet<string> = new Set(["google", "apple", "facebook"]);

interface Pending {
  provider: ProviderId;
  state: string;
  /** Absent on a resumed flow whose authorize URL carried none. */
  nonce?: string;
  /** Absent when the provider has no PKCE (Apple), live or resumed. */
  verifier?: string;
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
      if (stored && !sessionExpired(stored, clock.nowMs())) {
        session.set(stored);
        status.set("authenticated");
      } else if (stored) {
        await store.clear();
      }
    } catch {
      // reported by the next sign-in, refresh or sign-out instead
    }
    await resumeParkedAuthorize();
  })();

  function redirectScheme(): string {
    return config.redirectUri.slice(0, config.redirectUri.indexOf("://"));
  }

  /** The shared preamble of every sign-in: clear the error, park authorizing, and supersede whatever flow ran before. */
  function beginSignIn(): { restoreStatus: AuthStatus; restoreError: AuthError | null } {
    const restoreStatus = status();
    const restoreError = error();
    error.set(null);
    status.set("authorizing");
    const previous = pending;
    pending = null;
    generation += 1;
    previous?.reject(new AuthError("unknown", "superseded by a new sign-in"));
    return { restoreStatus, restoreError };
  }

  async function signIn(provider: ProviderId): Promise<void> {
    const restore = beginSignIn();
    const epoch = generation;
    // The native SDK leg first, on any host: a missing channel — whole-channel
    // or per provider (Android has no native apple leg) — falls through to the
    // browser below, while a cancel or SDK failure stops here — no double-flow
    // after a real answer.
    if (hostAvailable() && NATIVE_SIGN_IN_PROVIDERS.has(provider)) {
      const outcome = await runNativeSignIn(provider as NativeSignInProvider, restore);
      if (outcome === "done") return;
      // Absent channel, but a sign-out or a newer sign-in took over meanwhile:
      // this flow is dead, not deferred.
      if (generation !== epoch) return;
    }
    return browserSignIn(provider);
  }

  /** The browser launcher: build the authorize URL, park the flow, open the surface. */
  async function browserSignIn(provider: ProviderId): Promise<void> {
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
    return new Promise<void>((resolve, reject) => {
      pending = { provider, state, nonce, verifier, scopes: scopes.join(" "), resolve, reject };
      void launch(url);
    });
  }

  async function signInNative(provider: ProviderId, options?: { audience?: string }): Promise<void> {
    if (!NATIVE_SIGN_IN_PROVIDERS.has(provider)) {
      throw new AuthError("unknown", `native sign-in serves google, apple and facebook, not ${provider}`);
    }
    const restore = beginSignIn();
    const outcome = await runNativeSignIn(provider as NativeSignInProvider, restore, options?.audience);
    if (outcome === "absent") {
      const authError = new AuthError("no_launcher", `this host has no native sign-in channel for ${provider}`);
      status.set("error");
      error.set(authError);
      throw authError;
    }
  }

  type NativeOutcome = "absent" | "done";

  /** Runs the native SDK leg and settles the signals itself: "absent" means no channel (the caller falls back to the browser); otherwise it resolves "done" or throws with the failure already reported. */
  async function runNativeSignIn(
    provider: NativeSignInProvider,
    restore: { restoreStatus: AuthStatus; restoreError: AuthError | null },
    audience?: string,
  ): Promise<NativeOutcome> {
    const epoch = generation;
    // The raw nonce rides the channel call in clear; the hosts bind it per
    // provider rule — Apple hashes it into the request and the id token,
    // Google's Credential Manager compares it verbatim (see the legs).
    const rawNonce = createNonce();
    let result: NativeSignInResult;
    try {
      const answered = await nativeSignIn({ provider, nonce: rawNonce });
      if (!answered) return "absent";
      result = answered;
    } catch (cause) {
      if (generation !== epoch) throw toAuthError(cause);
      if (nativeCancelled(cause)) {
        // The user backed out before anything happened: restore the state the
        // sign-in found and report nothing on the signals.
        status.set(restore.restoreStatus);
        error.set(restore.restoreError);
        throw new AuthError("access_denied", "the native sign-in was cancelled");
      }
      const authError = toAuthError(cause);
      status.set("error");
      error.set(authError);
      throw authError;
    }
    status.set("exchanging");
    try {
      await publishNativeSession(provider, result, rawNonce, audience, epoch);
      return "done";
    } catch (cause) {
      const authError = toAuthError(cause);
      if (generation !== epoch) throw authError;
      status.set("error");
      error.set(authError);
      throw authError;
    }
  }

  /** Completes a native SDK result into a session: verify per the provider's nonce rule, then the same store save and signal publish as the browser path. */
  async function publishNativeSession(
    provider: NativeSignInProvider,
    result: NativeSignInResult,
    rawNonce: string,
    audience: string | undefined,
    epoch: number,
  ): Promise<void> {
    if (result.provider !== provider) {
      throw new AuthError("unknown", `the host answered with ${result.provider}, not ${provider}`);
    }
    // The echo must be the nonce the core sent; the id token's own claim is
    // checked per provider rule below.
    if (result.nonce !== undefined && result.nonce !== rawNonce) {
      throw new AuthError("nonce_mismatch", "the native sign-in echoed a nonce the core did not send");
    }
    const providerInfo = providerConfig(provider, mockBaseUrl);
    const fallbackScope = providerInfo.defaultScopes.join(" ");
    let next: Session;
    let raw: Record<string, unknown>;
    if (provider === "google" && result.serverAuthCode) {
      // google on iOS: the serverAuthCode is the SERVER (web) client's grant,
      // redeemed with that client's secret, which only the broker holds — so a
      // configured broker owns the leg. The direct call stays for sandbox
      // tests, whose transport plays Google's token endpoint.
      const exchangeConfig: ProviderConfig = config.brokerUrl ? { ...providerInfo, needsBroker: true } : providerInfo;
      const response = await exchangeCode({
        config: exchangeConfig,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        code: result.serverAuthCode,
        brokerUrl: config.brokerUrl,
        nowMs: () => clock.nowMs(),
        fallbackScope,
      });
      // The exchanged id token is bound by its single-use code, not by a nonce
      // this flow chose — the SDK leg sent none — so no nonce check here.
      let claims: Record<string, unknown> | null = null;
      if (response.idToken && providerInfo.jwksUrl) {
        claims = await verifyIdToken({
          idToken: response.idToken,
          jwksUrl: providerInfo.jwksUrl,
          issuer: providerInfo.issuer,
          audience: config.clientId,
          nowMs: () => clock.nowMs(),
        });
      }
      if (providerInfo.userinfoUrl) {
        raw = await fetchUserInfo(providerInfo.userinfoUrl, response.accessToken);
      } else if (claims) {
        raw = claims;
      } else {
        throw new AuthError("unknown", "neither userinfo nor id-token claims came back");
      }
      next = {
        provider,
        accessToken: response.accessToken,
        refreshToken: response.refreshToken,
        idToken: response.idToken,
        expiresAt: response.expiresAt,
        scope: response.scope,
      };
    } else if (provider === "google" && result.idToken) {
      // google on Android: aud is the server (web) client id —
      // nativeAudiences.google, not clientId — and Google's rule compares the
      // nonce VERBATIM.
      const built = await idTokenSession(
        provider,
        providerInfo,
        result.idToken,
        { audience: audience ?? config.nativeAudiences?.google, audienceField: "nativeAudiences.google", nonceRule: "verbatim" },
        rawNonce,
        () => clock.nowMs(),
      );
      next = built.session;
      raw = built.claims;
    } else if (provider === "apple" && result.identityToken) {
      // apple on iOS: aud is the app's bundle id, and Apple's rule is the
      // opposite of Google's — the request carried sha256(raw), so the token's
      // nonce claim is the hash and verification hashes the raw nonce again.
      const built = await idTokenSession(
        provider,
        providerInfo,
        result.identityToken,
        { audience: audience ?? config.nativeAudiences?.apple, audienceField: "nativeAudiences.apple", nonceRule: "sha256" },
        rawNonce,
        () => clock.nowMs(),
      );
      // The code is single-use and its exchange needs an Apple client secret,
      // so the broker owns that leg; the session keeps the code for the server.
      next = { ...built.session, authorizationCode: result.authorizationCode };
      raw = built.claims;
    } else if (provider === "facebook" && result.accessToken) {
      // facebook: the SDK leg issues an opaque Graph token outright — no
      // exchange, no JWKS. Without a host-reported expiry the session never
      // expires locally (expiresAt 0), per the Session contract.
      next = {
        provider,
        accessToken: result.accessToken,
        expiresAt: typeof result.expiresAt === "number" ? result.expiresAt : 0,
        scope: fallbackScope,
      };
      if (!providerInfo.userinfoUrl) throw new AuthError("unknown", "facebook has no userinfo endpoint");
      raw = await fetchUserInfo(providerInfo.userinfoUrl, result.accessToken);
    } else {
      throw new AuthError("unknown", `the host returned no ${provider} credential the core can consume`);
    }
    // A sign-out or a newer sign-in during the leg owns the state now; never
    // apply this session across an epoch change.
    if (generation !== epoch) throw new AuthError("unknown", "cancelled by a sign-out or a newer sign-in");
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
    user.set(mapUserInfo(provider, raw));
    status.set("authenticated");
    error.set(null);
  }

  async function launch(url: string): Promise<void> {
    const waiting = pending;
    if (!waiting) return;
    try {
      if (hostAvailable()) {
        const callbackUrl = await hostAuthorize(url, redirectScheme(), {
          verifier: waiting.verifier,
          state: waiting.state,
          provider: waiting.provider,
        });
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

  // Process death between authorize and redirect leaves the host holding a
  // parked record. At boot: a record with a callback finishes that flow; one
  // without is reported, never re-launched, and left parked — its redirect
  // may still arrive, and a new sign-in supersedes it host-side.
  async function resumeParkedAuthorize(): Promise<void> {
    const record = await loadPendingAuthorize();
    // A sign-in started while the record was read owns the channel: the
    // record is that flow's, not a dead one's.
    if (!record || pending) return;
    const waiting = pendingFromRecord(record);
    if (record.callbackUrl && waiting) {
      pending = waiting;
      const epoch = generation;
      try {
        await deliverRedirect(record.callbackUrl);
      } catch {
        // deliverRedirect reported the failure on the signals; either way the
        // parked record is consumed now.
      }
      // A sign-in launched while the resume ran sealed its own record; only
      // clear when that flow is not the one now parked.
      if (generation === epoch || !pending) await clearPendingAuthorize();
      return;
    }
    if (!waiting) await clearPendingAuthorize();
    error.set(new AuthError("interrupted", "a previous sign-in did not finish; start it again"));
    if (!session()) status.set("error");
  }

  function pendingFromRecord(record: PendingAuthorize): Pending | null {
    if (!record.url || !record.state || !record.provider) return null;
    let url: URL;
    try {
      url = new URL(record.url);
    } catch {
      return null;
    }
    const provider = record.provider as ProviderId;
    const providerInfo: ProviderConfig | undefined = providerConfig(provider, mockBaseUrl);
    // An unknown provider id falls through the config switch to undefined.
    if (!providerInfo || providerInfo.id !== provider) return null;
    // Fail closed: a record that cannot answer for its state, that would skip
    // nonce binding, or that can never pass the exchange is unusable.
    if (url.searchParams.get("state") !== record.state) return null;
    if (providerInfo.wantsNonce && !url.searchParams.get("nonce")) return null;
    if (providerInfo.usePkce && !record.verifier) return null;
    const scope = url.searchParams.get("scope");
    return {
      provider,
      state: record.state,
      nonce: url.searchParams.get("nonce") ?? undefined,
      verifier: record.verifier,
      scopes: scope && scope.trim() ? scope : providerInfo.defaultScopes.join(" "),
      resolve: () => {},
      reject: () => {},
    };
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

  // Every action runs untracked: their preambles read the very signals they
  // write (beginSignIn reads status for the cancel-restore), and a caller
  // invoking one inside an effect would subscribe to them — each write then
  // re-ran that effect and re-entered the action, superseding its own flow.
  return {
    session,
    user,
    status,
    error,
    signIn: (provider: ProviderId): Promise<void> => untracked(() => signIn(provider)),
    signInNative: (provider: NativeSignInProvider, options?: { audience?: string }): Promise<void> =>
      untracked(() => signInNative(provider, options)),
    handleRedirect: (url: string): Promise<void> => untracked(() => deliverRedirect(url)),
    refresh: (): Promise<void> =>
      untracked(() => {
        // Single flight: parallel refreshes share the request in flight.
        refreshing ??= doRefresh().finally(() => {
          refreshing = null;
        });
        return refreshing;
      }),
    signOut: (): Promise<void> => untracked(() => signOut()),
  };
}

function callbackError(error: string, description: string | null): AuthError {
  if (error === "access_denied") return new AuthError("access_denied", description ?? "the user denied the request");
  if (error === "expired_token" || error === "expired_code" || error === "authorization_expired") {
    return new AuthError("expired_code", description ?? error);
  }
  return new AuthError("unknown", description ?? error);
}

/** Builds the id-token-only session of a native SDK leg that issued no tokens beyond the id token itself. */
async function idTokenSession(
  provider: ProviderId,
  providerInfo: ProviderConfig,
  idToken: string,
  checks: { audience?: string; audienceField: string; nonceRule: "verbatim" | "sha256" },
  rawNonce: string,
  nowMs: () => number,
): Promise<{ session: Session; claims: Record<string, unknown> }> {
  if (!checks.audience) {
    throw new AuthError("unknown", `native ${provider} sign-in needs ${checks.audienceField} in the config: the id token is issued for it, not clientId`);
  }
  if (!providerInfo.jwksUrl) throw new AuthError("unknown", `${provider} has no JWKS to verify the id token against`);
  const claims = await verifyIdToken({
    idToken,
    jwksUrl: providerInfo.jwksUrl,
    issuer: providerInfo.issuer,
    audience: checks.audience,
    // The nonce rules differ: Google's Credential Manager compares the raw
    // nonce verbatim; Apple's request carried sha256(raw), so the claim is the
    // hash and the raw nonce is hashed again before comparing.
    expectedNonce: checks.nonceRule === "verbatim" ? rawNonce : await sha256Hex(rawNonce),
    nowMs,
  });
  const exp = typeof claims.exp === "number" ? claims.exp : null;
  if (exp === null) throw new AuthError("unknown", "the id token has no exp to expire the session by");
  return {
    session: {
      provider,
      // The id token is the leg's only bearer credential; the session lives
      // exactly as long as it, and refresh has nothing to refresh.
      accessToken: idToken,
      idToken,
      expiresAt: exp * 1000,
      scope: providerInfo.defaultScopes.join(" "),
    },
    claims,
  };
}

/** The hosts reject a dismissed native surface with a "cancelled" message (their contract); any other rejection is an SDK or provider failure. */
function nativeCancelled(cause: unknown): boolean {
  const message = cause instanceof Error ? cause.message : String(cause);
  return message === "cancelled" || message.startsWith("cancelled");
}

function toAuthError(cause: unknown): AuthError {
  return cause instanceof AuthError ? cause : new AuthError("unknown", cause instanceof Error ? cause.message : String(cause));
}
