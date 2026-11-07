import { generateKeyPairSync, createSign, createHash } from "node:crypto";

// One RSA keypair per boot: id_tokens are only verifiable against the JWKS of the
// live server, so a restart intentionally invalidates previously issued tokens.
export function createKeyMaterial() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const kid = "nsh-sandbox-key-" + createHash("sha256").update(spki).digest("base64url").slice(0, 12);
  return { kid, publicKey, privateKey };
}

export function jwksDoc(key) {
  const jwk = key.publicKey.export({ format: "jwk" });
  return { keys: [{ kty: jwk.kty, use: "sig", alg: "RS256", kid: key.kid, n: jwk.n, e: jwk.e }] };
}

export function signJwt(key, claims) {
  const header = { alg: "RS256", typ: "JWT", kid: key.kid };
  const data = Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." + Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = createSign("RSA-SHA256").update(data).sign(key.privateKey, "base64url");
  return data + "." + sig;
}
