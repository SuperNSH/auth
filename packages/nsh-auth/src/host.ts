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
