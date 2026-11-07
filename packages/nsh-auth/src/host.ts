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
      const answer = await host.call<{ value: Session | null }>("auth.store.load", { key: this.key });
      return answer.value ?? null;
    } catch (error) {
      throw new AuthError("store_error", `auth.store.load failed: ${String(error)}`);
    }
  }

  async save(session: Session): Promise<void> {
    try {
      await host.call("auth.store.save", { key: this.key, value: session });
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
export async function hostAuthorize(url: string, scheme: string): Promise<string> {
  try {
      const answer = await host.call<{ callbackUrl: string }>("auth.authorize", { url, scheme });
    if (typeof answer.callbackUrl !== "string" || !answer.callbackUrl) {
      throw new Error("the host returned no callbackUrl");
    }
    return answer.callbackUrl;
  } catch (error) {
    throw new AuthError("no_launcher", `auth.authorize failed: ${String(error)}`);
  }
}
