import { base64urlDecode } from "./base64";
import { AuthError } from "./errors";

const RS256 = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;

// A subset of the runtime's JsonWebKey, which it imports structurally (kid is extra).
export interface Jwk {
  kty?: string;
  kid?: string;
  alg?: string;
  n?: string;
  e?: string;
  use?: string;
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}

export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError("unknown", "id token is not a JWT");
  try {
    const decoder = new TextDecoder();
    const header = JSON.parse(decoder.decode(base64urlDecode(parts[0]))) as Record<string, unknown>;
    const claims = JSON.parse(decoder.decode(base64urlDecode(parts[1]))) as Record<string, unknown>;
    return {
      header,
      claims,
      signingInput: new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
      signature: base64urlDecode(parts[2]),
    };
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw new AuthError("unknown", "id token is malformed");
  }
}

export interface VerifyOptions {
  idToken: string;
  jwksUrl: string;
  audience: string;
  issuer?: string | null;
  expectedNonce?: string;
  nowMs: () => number;
}

/** RS256-verifies an id token against the provider's JWKS, then checks its claims. Returns the claims. */
export async function verifyIdToken(options: VerifyOptions): Promise<Record<string, unknown>> {
  const jwt = decodeJwt(options.idToken);
  if (jwt.header.alg !== "RS256") {
    throw new AuthError("unknown", `id token alg ${String(jwt.header.alg)} is not RS256`);
  }
  let keys: Jwk[];
  try {
    const response = await fetch(options.jwksUrl);
    if (!response.ok) throw new Error(`status ${response.status}`);
    const body = (await response.json()) as { keys?: Jwk[] };
    keys = body.keys ?? [];
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw new AuthError("network", `JWKS fetch failed: ${String(error)}`);
  }
  const kid = typeof jwt.header.kid === "string" ? jwt.header.kid : null;
  const candidates = keys.filter((key) => key.kty === "RSA" && (kid === null || key.kid === kid));
  if (candidates.length === 0) throw new AuthError("unknown", "no JWKS key matches the id token");
  let verified = false;
  let lastError: unknown = null;
  for (const jwk of candidates) {
    try {
      const key = await crypto.subtle.importKey("jwk", jwk, RS256, false, ["verify"]);
      verified = await crypto.subtle.verify(RS256, key, jwt.signature, jwt.signingInput);
      if (verified) break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!verified) {
    throw new AuthError("unknown", `id token signature did not verify${lastError ? `: ${String(lastError)}` : ""}`);
  }
  checkClaims(jwt.claims, options);
  return jwt.claims;
}

function checkClaims(claims: Record<string, unknown>, options: VerifyOptions): void {
  const now = options.nowMs() / 1000;
  const exp = typeof claims.exp === "number" ? claims.exp : null;
  if (exp === null || exp <= now) throw new AuthError("unknown", "id token is expired or has no exp");
  const aud = claims.aud;
  const audience = typeof aud === "string" ? aud : Array.isArray(aud) ? aud.find((a): a is string => a === options.audience) : undefined;
  if (audience !== options.audience) throw new AuthError("unknown", "id token is not for this client");
  if (options.issuer && claims.iss !== options.issuer) {
    throw new AuthError("unknown", `id token iss ${String(claims.iss)} is not ${options.issuer}`);
  }
  if (options.expectedNonce !== undefined && claims.nonce !== options.expectedNonce) {
    throw new AuthError("nonce_mismatch", "id token nonce does not match the one sent");
  }
}
