/** Every failure the auth loop reports, on `error` or as the rejection of the call that caused it. */
export type AuthErrorCode =
  | "access_denied"
  | "state_mismatch"
  | "nonce_mismatch"
  | "expired_code"
  | "invalid_grant"
  | "network"
  | "broker_error"
  | "store_error"
  | "no_launcher"
  | "unknown";

export class AuthError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string) {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
}
