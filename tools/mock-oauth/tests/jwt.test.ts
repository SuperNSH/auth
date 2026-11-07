import { describe, test, expect } from "bun:test";
import { createPublicKey, createVerify } from "node:crypto";
import { authorizeOnly, decodeJwt, fullFlow, get, url, withMock } from "./helpers.ts";

async function jwksKey(m: any, prov: string) {
  const res = await get(url(m, prov, "jwks"));
  expect(res.status).toBe(200);
  const key = res.body.keys[0];
  expect(key.kty).toBe("RSA");
  expect(key.alg).toBe("RS256");
  expect(key.kid).toMatch(/^nsh-sandbox-key-/);
  return key;
}

function verifyRs256(jwt: string, key: any): boolean {
  const [data, sig] = [jwt.split(".").slice(0, 2).join("."), jwt.split(".")[2]];
  const pub = createPublicKey({ key: { kty: key.kty, n: key.n, e: key.e }, format: "jwk" });
  return createVerify("RSA-SHA256").update(data).verify(pub, sig, "base64url");
}

const ISSUERS: Record<string, string> = {
  google: "google",
  apple: "apple",
  microsoft: "microsoft/common",
  facebook: "facebook",
  oidc: "oidc",
  mock: "mock",
};

describe("id_token is a real RS256 JWT verifiable against the served JWKS", () => {
  for (const prov of Object.keys(ISSUERS)) {
    test(`${prov}: signature, header kid, iss, aud, sub, email, exp`, async () => {
      await withMock(async (m) => {
        // Facebook only issues an id_token in its openid mode.
        const flow = await fullFlow(m, prov, prov === "facebook" ? { scope: "openid,public_profile" } : {});
        const idToken = flow.token.body.id_token;
        expect(idToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
        const { header, claims } = decodeJwt(idToken);
        expect(header.alg).toBe("RS256");
        const key = await jwksKey(m, prov);
        expect(header.kid).toBe(key.kid);
        expect(verifyRs256(idToken, key)).toBe(true);
        expect(claims.iss).toBe(`${m.base}/${ISSUERS[prov]}`);
        expect(claims.aud).toBe("nsh-auth-sandbox-client");
        expect(claims.email).toBe("sandbox.user@nsh-auth.invalid");
        expect(claims.exp).toBeGreaterThan(claims.iat);
        // provider-stable subject
        if (prov === "google") expect(claims.sub).toBe("nsh-sandbox-google-user-0001");
        if (prov === "apple") {
          expect(claims.sub).toBe("000000.nsh-sandbox.0000");
          expect(claims.email_verified).toBe("true"); // Apple encodes booleans as strings
        }
        if (prov === "microsoft") {
          expect(claims.tid).toBe("common");
          expect(claims.preferred_username).toBe("sandbox.user@nsh-auth.invalid");
        }
      });
    });
  }

  test("nonce from authorize lands in the id_token (client can detect a mismatch)", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google", { nonce: "n0nce-abc" });
      const { claims } = decodeJwt(flow.token.body.id_token);
      expect(claims.nonce).toBe("n0nce-abc");
    });
  });

  test("no nonce claim when authorize had none", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google");
      const { claims } = decodeJwt(flow.token.body.id_token);
      expect(claims.nonce).toBeUndefined();
    });
  });

  test("a tampered payload fails signature verification", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "mock");
      const parts = flow.token.body.id_token.split(".");
      const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      claims.sub = "attacker";
      const forged = [parts[0], Buffer.from(JSON.stringify(claims)).toString("base64url"), parts[2]].join(".");
      const key = await jwksKey(m, "mock");
      expect(verifyRs256(forged, key)).toBe(false);
    });
  });

  test("google: no id_token when scope omits openid", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google", { scope: "email profile", access_type: "online" });
      expect(flow.token.body.id_token).toBeUndefined();
    });
  });
});
