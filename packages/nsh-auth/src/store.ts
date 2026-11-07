import type { Session, SessionStore } from "./types";

/** Holds the session in memory only: nothing survives the process. */
export class MemoryStore implements SessionStore {
  private stored: Session | null = null;

  async load(): Promise<Session | null> {
    return this.stored;
  }

  async save(session: Session): Promise<void> {
    this.stored = session;
  }

  async clear(): Promise<void> {
    this.stored = null;
  }
}
