import type { Signal } from "nsh";
import type { AuthError } from "./errors";
import type { ProviderId } from "./providers";

export type { AuthErrorCode } from "./errors";
export type { ProviderId } from "./providers";


export type AuthStatus = "idle" | "authorizing" | "exchanging" | "authenticated" | "refreshing" | "error";

export interface Session {
  provider: ProviderId;
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  /** Apple's native sign-in keeps its single-use authorization code here for the server (broker) exchange; the session itself stands on the verified identity token. */
  authorizationCode?: string;
  /** Wall-clock milliseconds after which the access token is dead; refresh extends it. */
  expiresAt: number;
  scope: string;
}

/**
 * Sessions expiring within this margin count as expired, so no token is spent
 * on a request it cannot outlive (AppAuth's OIDAuthState uses the same 60 s).
 */
export const EXPIRY_TOLERANCE_MS = 60_000;

/** True when the session is dead or dies within `EXPIRY_TOLERANCE_MS` of `nowMs`; `expiresAt` 0 never expires. */
export function sessionExpired(session: Session, nowMs: number): boolean {
  return session.expiresAt !== 0 && nowMs + EXPIRY_TOLERANCE_MS >= session.expiresAt;
}

export interface UserInfo {
  id: string;
  name?: string;
  email?: string;
  picture?: string;
  raw: unknown;
}

export interface AuthConfig {
  clientId: string;
  redirectUri: string;
  /** Per-provider overrides of the defaults in `providers.ts`. */
  scopes?: Partial<Record<ProviderId, string[]>>;
  mockBaseUrl?: string;
  /** Where confidential-client providers (GitHub, Apple) exchange codes; runs on the app owner's server. */
  brokerUrl?: string;
  /**
   * Audiences the native SDK legs' id tokens are issued for — google: the web
   * (server) client id Credential Manager puts in `aud`; apple: the app's
   * bundle id. The browser path checks `clientId` instead; these legs cannot.
   */
  nativeAudiences?: { google?: string; apple?: string };
  /** auto: the host's secure store when a host embeds the app, memory otherwise. */
  storage?: "auto" | "host" | "memory";
  /** Where wall-clock time comes from; defaults to `Date.now`. Tests inject a manual one. */
  clock?: { nowMs(): number };
  /** Called with each authorize URL a signIn builds (a harness or log can show it). */
  onAuthorizeUrl?: (url: string) => void;
}

export interface Auth {
  session: Signal<Session | null>;
  user: Signal<UserInfo | null>;
  status: Signal<AuthStatus>;
  error: Signal<AuthError | null>;
  signIn(provider: ProviderId): Promise<void>;
  /** The native SDK leg only (google, apple, facebook): no browser fallback — rejects with `no_launcher` when the host has no channel. */
  signInNative(provider: ProviderId, options?: { audience?: string }): Promise<void>;
  handleRedirect(url: string): Promise<void>;
  refresh(): Promise<void>;
  signOut(): Promise<void>;
}

export interface SessionStore {
  load(): Promise<Session | null>;
  save(session: Session): Promise<void>;
  clear(): Promise<void>;
}
