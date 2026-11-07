import { base64urlEncode } from "./base64";

// RFC 7636 4.1: 32 octets is the stated minimum and gives the 43-char verifier.
const VERIFIER_BYTES = 32;
const STATE_BYTES = 16;

function randomBase64url(bytes: number): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return base64urlEncode(data);
}

export function createCodeVerifier(): string {
  return randomBase64url(VERIFIER_BYTES);
}

export function createState(): string {
  return randomBase64url(STATE_BYTES);
}

export function createNonce(): string {
  return randomBase64url(STATE_BYTES);
}

export async function codeChallengeS256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64urlEncode(new Uint8Array(digest));
}

/** Lowercase hex SHA-256: Apple's native sign-in carries this hash of the raw nonce in both the request and the id token's nonce claim. */
export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
