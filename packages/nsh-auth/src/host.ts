import { host } from "nsh";
import { AuthError } from "./errors";
import type { Session, SessionStore } from "./types";

export function hostAvailable(): boolean {
  return host.available();
}

/**
 * Secure storage through the embedding host (Keychain, Keystore, DPAPI or
 * Secret Service behind it). Plain `Storage` is deliberately not used: it
 * cannot hold tokens safely.
 */
export class HostStore implements SessionStore {
  constructor(private readonly key: string) {}

  async load(): Promise<Session | null> {
    try {
      const answer = await host.call<{ value: Session | string | null }>("auth.store.load", { key: this.key });
      // The hosts keep the value as a JSON string (Keychain, Keystore); a
      // string that does not parse is absent data, not a store failure.
      if (typeof answer.value !== "string") return answer.value ?? null;
      try {
        return (JSON.parse(answer.value) as Session) ?? null;
      } catch {
        return null;
      }
    } catch (error) {
      throw new AuthError("store_error", `auth.store.load failed: ${String(error)}`);
    }
  }

  async save(session: Session): Promise<void> {
    try {
      // Hosts keep the value as a JSON string (Android's requireString
      // rejects objects) — mirrors load's parse.
      await host.call("auth.store.save", { key: this.key, value: JSON.stringify(session) });
    } catch (error) {
      throw new AuthError("store_error", `auth.store.save failed: ${String(error)}`);
    }
  }

  async clear(): Promise<void> {
    try {
      await host.call("auth.store.clear", { key: this.key });
    } catch (error) {
      throw new AuthError("store_error", `auth.store.clear failed: ${String(error)}`);
    }
  }
}

/** Asks the host to open the authorize surface (ASWebAuthenticationSession, Custom Tabs) and return the callback it caught. */
export async function hostAuthorize(url: string, scheme: string, provenance?: AuthorizeProvenance): Promise<string> {
  try {
    const answer = await host.call<{ callbackUrl: string }>("auth.authorize", { url, scheme, ...provenance });
    if (typeof answer.callbackUrl !== "string" || !answer.callbackUrl) {
      throw new Error("the host returned no callbackUrl");
    }
    return answer.callbackUrl;
  } catch (error) {
    throw new AuthError("no_launcher", `auth.authorize failed: ${String(error)}`);
  }
}

/** The flow facts the host seals next to its parked record, so process death can still finish the exchange. */
export interface AuthorizeProvenance {
  verifier?: string;
  state?: string;
  provider?: string;
}

/** The host's parked authorize record (`auth.pendingAuthorize`); it holds no tokens. */
export interface PendingAuthorize extends AuthorizeProvenance {
  scheme: string;
  url?: string;
  /** Set once the redirect for the parked flow has arrived. */
  callbackUrl?: string;
}

/** Reads the parked record of a sign-in killed by process death: null when nothing is parked, or when the host predates the channel. */
export async function loadPendingAuthorize(): Promise<PendingAuthorize | null> {
  if (!hostAvailable()) return null;
  try {
    const answer = await host.call<PendingAuthorize | null>("auth.pendingAuthorize", {});
    // Android answers emptyMap() when nothing is parked: an empty or non-object
    // reply is "nothing". A reply with keys stays a record and fails closed on
    // resume if its fields do not hold.
    if (!answer || typeof answer !== "object" || Object.keys(answer).length === 0) return null;
    return answer;
  } catch {
    return null;
  }
}

/** Consumes the parked record once its flow is finished or unusable. */
export async function clearPendingAuthorize(): Promise<void> {
  if (!hostAvailable()) return;
  try {
    await host.call("auth.pendingAuthorize", { clear: true });
  } catch {
    // A record left behind costs one spurious resume, which then clears it.
  }
}

/** The providers whose native SDK legs the sign-in channel serves. */
export type NativeSignInProvider = "google" | "apple" | "facebook";

/**
 * What the host answers `auth.nativeSignIn` with — the artifact differs per
 * platform (the pinned channel contract): google on iOS carries
 * `serverAuthCode` (the server client's grant, redeemed by the broker),
 * google on Android carries `idToken` (aud = the web client id), apple carries
 * `identityToken` plus `authorizationCode` with the RAW nonce echoed, and
 * facebook carries the opaque Graph `accessToken`.
 */
export interface NativeSignInResult {
  provider: NativeSignInProvider;
  /** google on iOS: the server (web) client's authorization code. */
  serverAuthCode?: string;
  /** google on Android: the provider's id token (RS256 JWT, aud = the web client id). */
  idToken?: string;
  /** apple: the identity token (RS256 JWT, aud = the app bundle id). */
  identityToken?: string;
  /** apple: the single-use code; exchanging it needs an Apple client secret, so the broker owns that leg. */
  authorizationCode?: string;
  /** facebook: the Graph API token. */
  accessToken?: string;
  /** facebook: epoch ms the host reported; absent means the token's lifetime is unknown. */
  expiresAt?: number;
  /** The raw nonce echoed back (apple always, google when the request carried one). */
  nonce?: string;
}

/**
 * Asks the host to run the provider's native SDK sign-in. `nonce` is the RAW
 * nonce: the hosts bind it per provider rule (Apple hashes it into the
 * request, Google's Credential Manager uses it verbatim). Returns null when
 * there is no channel for this provider — no host, not granted, an embedder
 * that predates the channel, or a host whose native module does not serve
 * this provider (Android implements google and facebook only) — so the caller
 * falls back to the browser; a rejected call (the sheet was dismissed, or the
 * SDK failed) throws instead.
 */
export async function nativeSignIn(request: { provider: NativeSignInProvider; nonce?: string }): Promise<NativeSignInResult | null> {
  if (!hostAvailable()) return null;
  try {
    const answer = await host.call<NativeSignInResult>("auth.nativeSignIn", request);
    if (!answer || typeof answer !== "object") throw new AuthError("unknown", "the host returned no native sign-in result");
    return answer;
  } catch (error) {
    // Both absence classes leave the browser as the provider's launcher; a
    // judged failure (cancelled, SDK or provider error) still throws.
    if (channelAbsent(error) || providerAbsent(error)) return null;
    throw error;
  }
}

/**
 * True when a `host.call` rejection means the channel itself is missing rather
 * than a failed sign-in: no host, not granted, or the engine's "handles no"
 * answer from an embedder built before the channel existed. Anything else is
 * the host judging the sign-in (cancelled, or an SDK failure).
 */
function channelAbsent(error: unknown): boolean {
  const code = typeof error === "object" && error !== null ? (error as { code?: unknown }).code : undefined;
  if (code === "ERR_ACCESS_DENIED" || code === "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM") return true;
  if (code === "ERR_NSH_HOST_ERROR") {
    const message = error instanceof Error ? error.message : String(error);
    return message.includes("handles no");
  }
  return false;
}

/**
 * True when the host answers the channel but has no native leg for THIS
 * provider: both pinned modules reject an unknown provider name with the
 * channel prefix plus the "unknown provider" phrase (`auth.nativeSignIn:
 * unknown provider "apple" (known: google, facebook)` on Android, bare on
 * iOS), delivered verbatim with code ERR_NSH_HOST_ERROR. SDK and provider
 * failures carry at most one marker — Credential Manager's and Facebook's
 * messages have no prefix, iOS's prefixed config failures lack the phrase —
 * so only this exact class falls back to the browser.
 */
function providerAbsent(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes("auth.nativeSignIn") && message.includes("unknown provider");
}
