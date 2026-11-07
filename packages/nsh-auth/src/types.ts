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
  /** Wall-clock milliseconds after which the access token is dead; refresh extends it. */
  expiresAt: number;
  scope: string;
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
  handleRedirect(url: string): Promise<void>;
  refresh(): Promise<void>;
  signOut(): Promise<void>;
}

export interface SessionStore {
  load(): Promise<Session | null>;
  save(session: Session): Promise<void>;
  clear(): Promise<void>;
}
