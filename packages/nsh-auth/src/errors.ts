/** Every failure the auth loop reports, on `error` or as the rejection of the call that caused it. */
export type AuthErrorCode =
  | "access_denied"
  | "state_mismatch"
  | "nonce_mismatch"
  | "expired_code"
  | "invalid_grant"
  | "network"
  | "server_error"
  | "broker_error"
  | "store_error"
  | "no_launcher"
  | "interrupted"
  | "unknown";

export class AuthError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string) {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }

  /**
   * Aligned with the Rust core: transport errors and any 5xx are transient;
   * every OAuth protocol failure is final. The broker follows the same status
   * split — its 5xx reports as `server_error` (retryable), its 4xx as
   * `broker_error` (final).
   */
  isRetryable(): boolean {
    return this.code === "network" || this.code === "server_error";
  }
}
