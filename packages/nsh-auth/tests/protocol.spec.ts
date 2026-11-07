// Protocol units under bun: loopback server only, fake clock only.
// Excluded from the nsh build and from `nsh test` (see tsconfig.json); run with `bun test tests/protocol.spec.ts`.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { buildAuthorizeUrl } from "../src/authorize";
import { base64urlDecode, base64urlEncode } from "../src/base64";
import { parseCallback } from "../src/callback";
import { AuthError } from "../src/errors";
import { decodeJwt, verifyIdToken } from "../src/jwks";
import { codeChallengeS256, createCodeVerifier, createNonce, createState, sha256Hex } from "../src/pkce";
import { providerConfig } from "../src/providers";
import { sessionExpired, type Session } from "../src/types";
import { exchangeCode, refreshTokens, revokeToken } from "../src/tokens";
import { mapUserInfo } from "../src/userinfo";

interface Hit {
  method: string;
  path: string;
  query: string;
  body: string | null;
  headers: Record<string, string>;
}

const hits: Hit[] = [];
let behavior: { tokenError?: { status: number; error: string; description: string }; idToken?: string } = {};
let server: Bun.Server;
let base = "";

let rsaKeys: { publicJwk: Record<string, unknown>; sign(input: Uint8Array): Promise<ArrayBuffer> };

async function signIdToken(claims: Record<string, unknown>): Promise<string> {
  const encoder = new TextEncoder();
  const part = (value: unknown) => base64urlEncode(encoder.encode(JSON.stringify(value)));
  const input = `${part({ alg: "RS256", kid: "spec-key", typ: "JWT" })}.${part(claims)}`;
  const signature = await rsaKeys.sign(encoder.encode(input));
  return `${input}.${base64urlEncode(new Uint8Array(signature))}`;
}

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  );
  rsaKeys = {
    publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
    sign: (input: Uint8Array) => crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, input),
  };
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      hits.push({
        method: request.method,
        path: url.pathname,
        query: url.search,
        body: await request.text(),
        headers: Object.fromEntries(request.headers.entries()),
      });
      if (url.pathname === "/mock/token" || url.pathname === "/broker/token") {
        if (url.pathname === "/mock/token" && behavior.tokenError) {
          return Response.json({ error: behavior.tokenError.error, error_description: behavior.tokenError.description }, { status: behavior.tokenError.status });
        }
        if (url.pathname === "/broker/token") {
          return Response.json({ accessToken: "loopback-access", refreshToken: "loopback-refresh", expiresIn: 3600, scope: "openid profile email offline_access" });
        }
        return Response.json({
          access_token: "loopback-access",
          refresh_token: "loopback-refresh",
          id_token: behavior.idToken,
          expires_in: 3600,
          scope: "openid profile email offline_access",
        });
      }
      if (url.pathname === "/broker/revoke") return new Response(null, { status: 204 });
      if (url.pathname === "/mock/revoke") return Response.json({});
      if (url.pathname === "/mock/.well-known/jwks.json") {
        return Response.json({ keys: [{ ...rsaKeys.publicJwk, kid: "spec-key", alg: "RS256", use: "sig" }] });
      }
      if (url.pathname === "/mock/userinfo") {
        if (request.headers.get("authorization") !== "Bearer loopback-access") return new Response(null, { status: 401 });
        return Response.json({ sub: "user-9", name: "Loopback User", email: "loopback@example.com", picture: `${base}/avatar.png` });
      }
      return new Response(null, { status: 404 });
    },
  });
  base = `http://127.0.0.1:${server.port}`;
});

afterAll(() => {
  server.stop(true);
});

const ZERO_CLOCK = { nowMs: () => 0 };

async function challengeOf(verifier: string): Promise<string> {
  return base64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}

describe("base64url", () => {
  test("matches the RFC 4648 vectors", () => {
    const vector = (text: string, expected: string) => {
      expect(base64urlEncode(new TextEncoder().encode(text))).toBe(expected);
      expect(new TextDecoder().decode(base64urlDecode(expected))).toBe(text);
    };
    vector("", "");
    vector("f", "Zg");
    vector("fo", "Zm8");
    vector("foo", "Zm9v");
    vector("foob", "Zm9vYg");
    vector("fooba", "Zm9vYmE");
    vector("foobar", "Zm9vYmFy");
  });

  test("decodes binary round trips and rejects foreign characters", () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) bytes[i] = i;
    const encoded = base64urlEncode(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toHaveLength(256);
    for (let i = 0; i < 256; i++) expect(decoded[i]).toBe(i);
    expect(() => base64urlDecode("ab/c")).toThrow();
    expect(() => base64urlDecode("ab?c")).toThrow();
  });
});

describe("pkce", () => {
  test("the RFC 7636 appendix B vector holds", async () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    expect(await codeChallengeS256(verifier)).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  test("verifiers are 43 characters and state and nonce are distinct", async () => {
    const verifier = createCodeVerifier();
    expect(verifier).toHaveLength(43);
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(createState()).toHaveLength(22);
    expect(createNonce()).toHaveLength(22);
    expect(createState()).not.toBe(createState());
    expect(await challengeOf(verifier)).toHaveLength(43);
  });

  test("sha256Hex matches the FIPS vectors Apple's native nonce rule leans on", async () => {
    expect(await sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(await sha256Hex("abc")).toHaveLength(64);
    expect(await sha256Hex("abc")).not.toMatch(/[^0-9a-f]/);
  });
});

describe("authorize URLs", () => {
  test("the mock URL is byte-exact", () => {
    const url = buildAuthorizeUrl({
      provider: providerConfig("mock", "http://127.0.0.1:8755"),
      clientId: "sandbox-client",
      redirectUri: "nsh-auth-demo://callback",
      scopes: ["openid", "email"],
      codeChallenge: "challenge-43-chars-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      state: "state-22-aaaaaaaaaaaaa",
      nonce: "nonce-22-aaaaaaaaaaaaa",
    });
    expect(url).toBe(
      "http://127.0.0.1:8755/mock/authorize?response_type=code&client_id=sandbox-client&redirect_uri=" +
        "nsh-auth-demo%3A%2F%2Fcallback&scope=openid+email&state=state-22-aaaaaaaaaaaaa&nonce=nonce-22-aaaaaaaaaaaaa&" +
        "code_challenge=challenge-43-chars-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256",
    );
  });

  test("nonce and pkce land per the documented table", () => {
    const common = {
      clientId: "sandbox-client",
      redirectUri: "nsh-auth-demo://callback",
      scopes: ["s1"],
      codeChallenge: "c".repeat(43),
      state: "s".repeat(22),
      nonce: "n".repeat(22),
    };
    // Facebook's OIDC flow: S256 challenge and a required nonce.
    const facebook = buildAuthorizeUrl({ ...common, provider: providerConfig("facebook") });
    expect(facebook).toContain("https://www.facebook.com/v27.0/dialog/oauth?");
    expect(facebook).toContain("nonce=");
    expect(facebook).toContain("code_challenge_method=S256");
    // Apple authenticates with the client_secret JWT: no PKCE on the authorize leg.
    const apple = buildAuthorizeUrl({ ...common, provider: providerConfig("apple") });
    expect(apple).toContain("response_mode=form_post");
    expect(apple).toContain("nonce=");
    expect(apple).not.toContain("code_challenge");
    // GitHub: S256 challenge, no nonce (plain OAuth, not OIDC).
    const github = buildAuthorizeUrl({ ...common, provider: providerConfig("github") });
    expect(github).toContain("https://github.com/login/oauth/authorize?");
    expect(github).toContain("code_challenge_method=S256");
    expect(github).not.toContain("nonce=");
    // Google's refresh token rides on the documented extras.
    const google = buildAuthorizeUrl({ ...common, provider: providerConfig("google") });
    expect(google).toContain("access_type=offline");
    expect(google).toContain("prompt=consent");
  });
});

describe("callback parsing", () => {
  test("reads code and state from a custom-scheme query", () => {
    const callback = parseCallback("nsh-auth-demo://callback?code=abc&state=xyz");
    expect(callback).toEqual({ code: "abc", state: "xyz", error: null, errorDescription: null });
  });

  test("reads errors, and the fragment when the query is empty", () => {
    const denial = parseCallback("nsh-auth-demo://callback?error=access_denied&error_description=no");
    expect(denial).toEqual({ code: null, state: null, error: "access_denied", errorDescription: "no" });
    const fragment = parseCallback("https://app.example/redirect#code=f1&state=s1");
    expect(fragment.code).toBe("f1");
    expect(fragment.state).toBe("s1");
    const empty = parseCallback("nsh-auth-demo://callback");
    expect(empty).toEqual({ code: null, state: null, error: null, errorDescription: null });
  });
});

describe("token exchange", () => {
  test("posts the code with the verifier and maps the answer", async () => {
    hits.length = 0;
    behavior = {};
    const response = await exchangeCode({
      config: providerConfig("mock", base),
      clientId: "sandbox-client",
      redirectUri: "nsh-auth-demo://callback",
      code: "loop-code",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "openid profile email offline_access",
    });
    expect(response.accessToken).toBe("loopback-access");
    expect(response.refreshToken).toBe("loopback-refresh");
    expect(response.expiresAt).toBe(3_600_000);
    expect(response.scope).toBe("openid profile email offline_access");
    const hit = hits.find((entry) => entry.path === "/mock/token");
    const form = new URLSearchParams(hit?.body ?? "");
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe("loop-code");
    expect(form.get("client_id")).toBe("sandbox-client");
    expect(form.get("redirect_uri")).toBe("nsh-auth-demo://callback");
    expect(form.get("code_verifier")).toHaveLength(43);
  });

  test("facebook's exchange is a GET with the verifier in the query", async () => {
    hits.length = 0;
    const facebook = providerConfig("facebook");
    const url = facebook.tokenUrl ?? "";
    await exchangeCode({
      config: { ...facebook, tokenUrl: `${base}/mock/token` },
      clientId: "sandbox-client",
      redirectUri: "nsh-auth-demo://callback",
      code: "fb-code",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "public_profile email",
    });
    const hit = hits.find((entry) => entry.method === "GET" && entry.path === "/mock/token");
    expect(hit).toBeDefined();
    expect(hit?.query).toContain("code_verifier");
    expect(hit?.query).toContain("code=fb-code");
  });

  test("maps invalid_grant by whether the description says expired", async () => {
    behavior = { tokenError: { status: 400, error: "invalid_grant", description: "authorization code has expired" } };
    const expired = await exchangeCode({
      config: providerConfig("mock", base),
      clientId: "c",
      redirectUri: "r",
      code: "x",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    }).catch((error: AuthError) => error);
    expect(expired.code).toBe("expired_code");
    behavior = { tokenError: { status: 400, error: "invalid_grant", description: "bad verification code" } };
    const rejected = await exchangeCode({
      config: providerConfig("mock", base),
      clientId: "c",
      redirectUri: "r",
      code: "x",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    }).catch((error: AuthError) => error);
    expect(rejected.code).toBe("invalid_grant");
    behavior = { tokenError: { status: 400, error: "access_denied", description: "denied" } };
    const denied = await exchangeCode({
      config: providerConfig("mock", base),
      clientId: "c",
      redirectUri: "r",
      code: "x",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    }).catch((error: AuthError) => error);
    expect(denied.code).toBe("access_denied");
  });

  test("a dead endpoint is a network error", async () => {
    // Port 1 on loopback: nothing listens there, the connection refuses.
    const dead = providerConfig("mock", "http://127.0.0.1:1");
    const failure = await exchangeCode({
      config: dead,
      clientId: "c",
      redirectUri: "r",
      code: "x",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    }).catch((error: AuthError) => error);
    expect(failure.code).toBe("network");
  });

  test("token requests announce Accept: application/json", async () => {
    hits.length = 0;
    behavior = {};
    await exchangeCode({
      config: providerConfig("mock", base),
      clientId: "sandbox-client",
      redirectUri: "r",
      code: "loop-code",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    });
    await refreshTokens({
      config: providerConfig("mock", base),
      clientId: "sandbox-client",
      refreshToken: "old-refresh",
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    });
    const posted = hits.filter((entry) => entry.path === "/mock/token" && entry.method === "POST");
    expect(posted).toHaveLength(2);
    for (const hit of posted) expect(hit.headers["accept"]).toBe("application/json");
  });
});

describe("retryability", () => {
  test("transport and 5xx failures are transient; OAuth protocol failures are final", () => {
    expect(new AuthError("network", "x").isRetryable()).toBe(true);
    expect(new AuthError("server_error", "x").isRetryable()).toBe(true);
    const fatal = [
      "access_denied",
      "state_mismatch",
      "nonce_mismatch",
      "expired_code",
      "invalid_grant",
      "broker_error",
      "store_error",
      "no_launcher",
      "unknown",
    ] as const;
    for (const code of fatal) expect(new AuthError(code, "x").isRetryable()).toBe(false);
  });

  test("a 5xx token answer is server_error; a 400 keeps its OAuth error", async () => {
    behavior = { tokenError: { status: 502, error: "server_error", description: "upstream down" } };
    const crashed = await exchangeCode({
      config: providerConfig("mock", base),
      clientId: "c",
      redirectUri: "r",
      code: "x",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    }).catch((error: AuthError) => error);
    expect(crashed.code).toBe("server_error");
    expect(crashed.isRetryable()).toBe(true);
    behavior = { tokenError: { status: 400, error: "invalid_grant", description: "bad verification code" } };
    const rejected = await exchangeCode({
      config: providerConfig("mock", base),
      clientId: "c",
      redirectUri: "r",
      code: "x",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    }).catch((error: AuthError) => error);
    expect(rejected.code).toBe("invalid_grant");
    expect(rejected.isRetryable()).toBe(false);
  });
});

describe("the broker", () => {
  test("github exchanges through it, and refuses without one", async () => {
    hits.length = 0;
    const github = providerConfig("github");
    const response = await exchangeCode({
      config: github,
      clientId: "sandbox-client",
      redirectUri: "nsh-auth-demo://callback",
      code: "gh-code",
      codeVerifier: "v".repeat(43),
      brokerUrl: `${base}/broker`,
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "read:user user:email",
    });
    expect(response.accessToken).toBe("loopback-access");
    const hit = hits.find((entry) => entry.path === "/broker/token");
    const payload = JSON.parse(hit?.body ?? "{}") as Record<string, unknown>;
    expect(payload).toEqual({ provider: "github", code: "gh-code", codeVerifier: "v".repeat(43), redirectUri: "nsh-auth-demo://callback" });
    // AppAuth-Android sends this for GitHub, which answers form-encoded without it.
    expect(hit?.headers["accept"]).toBe("application/json");
    const refused = await exchangeCode({
      config: github,
      clientId: "c",
      redirectUri: "r",
      code: "x",
      codeVerifier: "v".repeat(43),
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    }).catch((error: AuthError) => error);
    expect(refused.code).toBe("broker_error");
  });

  test("apple's broker exchange carries no verifier — the catalog has no PKCE for it", async () => {
    hits.length = 0;
    await exchangeCode({
      config: providerConfig("apple"),
      clientId: "sandbox-client",
      redirectUri: "nsh-auth-demo://callback",
      code: "apple-code",
      codeVerifier: "v".repeat(43),
      brokerUrl: `${base}/broker`,
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "openid name email",
    });
    const payload = JSON.parse(hits.find((entry) => entry.path === "/broker/token")?.body ?? "{}") as Record<string, unknown>;
    expect(payload.provider).toBe("apple");
    expect(payload.codeVerifier).toBeUndefined();
  });

  test("refresh and revoke go through it too", async () => {
    hits.length = 0;
    const github = providerConfig("github");
    const refreshed = await refreshTokens({
      config: github,
      clientId: "c",
      refreshToken: "old-refresh",
      brokerUrl: `${base}/broker`,
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "s",
    });
    expect(refreshed.refreshToken).toBe("loopback-refresh");
    const refreshHit = hits.find((entry) => entry.path === "/broker/token");
    expect(JSON.parse(refreshHit?.body ?? "{}")).toEqual({ provider: "github", refreshToken: "old-refresh" });
    await revokeToken({ config: github, brokerUrl: `${base}/broker`, token: "dead-token" });
    expect(hits.some((entry) => entry.path === "/broker/revoke")).toBe(true);
  });
});

describe("direct refresh and revoke", () => {
  test("refresh posts the grant and revoke posts the token", async () => {
    hits.length = 0;
    behavior = {};
    const mock = providerConfig("mock", base);
    const refreshed = await refreshTokens({
      config: mock,
      clientId: "sandbox-client",
      refreshToken: "old-refresh",
      nowMs: ZERO_CLOCK.nowMs,
      fallbackScope: "openid",
    });
    expect(refreshed.accessToken).toBe("loopback-access");
    const refreshForm = new URLSearchParams(hits.find((entry) => entry.path === "/mock/token")?.body ?? "");
    expect(refreshForm.get("grant_type")).toBe("refresh_token");
    expect(refreshForm.get("refresh_token")).toBe("old-refresh");
    expect(refreshForm.get("client_id")).toBe("sandbox-client");
    await revokeToken({ config: mock, token: "dead-token" });
    const revokeForm = new URLSearchParams(hits.find((entry) => entry.path === "/mock/revoke")?.body ?? "");
    expect(revokeForm.get("token")).toBe("dead-token");
  });
});

describe("expiry tolerance", () => {
  const session = (expiresAt: number): Session => ({ provider: "mock", accessToken: "a", expiresAt, scope: "s" });

  test("a session expiring within the 60-second margin counts as expired", () => {
    expect(sessionExpired(session(30_000), 0)).toBe(true);
    expect(sessionExpired(session(60_000), 0)).toBe(true);
    expect(sessionExpired(session(60_001), 0)).toBe(false);
    expect(sessionExpired(session(120_000), 29_000)).toBe(false);
  });

  test("an expiry of 0 means no expiry, as GitHub tokens do not expire", () => {
    expect(sessionExpired(session(0), Number.MAX_SAFE_INTEGER)).toBe(false);
  });
});

describe("id tokens", () => {
  test("decodeJwt splits a token", () => {
    const token = signIdToken({ sub: "user-9" });
    return token.then((value) => {
      const decoded = decodeJwt(value);
      expect(decoded.header.alg).toBe("RS256");
      expect(decoded.claims.sub).toBe("user-9");
      expect(() => decodeJwt("not-a-jwt")).toThrow();
    });
  });

  test("a well-signed token verifies and returns its claims", async () => {
    behavior = {};
    const idToken = await signIdToken({
      iss: base,
      sub: "user-9",
      aud: "sandbox-client",
      nonce: "n".repeat(22),
      exp: 3600,
    });
    const claims = await verifyIdToken({
      idToken,
      jwksUrl: `${base}/mock/.well-known/jwks.json`,
      audience: "sandbox-client",
      issuer: base,
      expectedNonce: "n".repeat(22),
      nowMs: ZERO_CLOCK.nowMs,
    });
    expect(claims.sub).toBe("user-9");
  });

  test("a replayed nonce is nonce_mismatch", async () => {
    const idToken = await signIdToken({ iss: base, sub: "user-9", aud: "sandbox-client", nonce: "attacker", exp: 3600 });
    const failure = await verifyIdToken({
      idToken,
      jwksUrl: `${base}/mock/.well-known/jwks.json`,
      audience: "sandbox-client",
      expectedNonce: "n".repeat(22),
      nowMs: ZERO_CLOCK.nowMs,
    }).catch((error: AuthError) => error);
    expect(failure.code).toBe("nonce_mismatch");
  });

  test("a tampered signature, a foreign audience and an expired token all fail", async () => {
    const parts = (await signIdToken({ iss: base, sub: "user-9", aud: "sandbox-client", exp: 3600 })).split(".");
    const tampered = await verifyIdToken({
      idToken: `${parts[0]}.${parts[1]}.${parts[2].slice(0, -2)}aa`,
      jwksUrl: `${base}/mock/.well-known/jwks.json`,
      audience: "sandbox-client",
      nowMs: ZERO_CLOCK.nowMs,
    }).catch((error: AuthError) => error);
    expect(tampered.code).toBe("unknown");
    const foreign = await verifyIdToken({
      idToken: await signIdToken({ iss: base, sub: "user-9", aud: "someone-else", exp: 3600 }),
      jwksUrl: `${base}/mock/.well-known/jwks.json`,
      audience: "sandbox-client",
      nowMs: ZERO_CLOCK.nowMs,
    }).catch((error: AuthError) => error);
    expect(foreign.code).toBe("unknown");
    const expired = await verifyIdToken({
      idToken: await signIdToken({ iss: base, sub: "user-9", aud: "sandbox-client", exp: 0 }),
      jwksUrl: `${base}/mock/.well-known/jwks.json`,
      audience: "sandbox-client",
      nowMs: () => 7_200_000,
    }).catch((error: AuthError) => error);
    expect(expired.code).toBe("unknown");
  });
});

describe("user mapping", () => {
  test("reads each provider's shape", () => {
    const claims = mapUserInfo("google", { sub: "g1", name: "G User", email: "g@example.com", picture: "https://x/p.png" });
    expect(claims).toMatchObject({ id: "g1", name: "G User", email: "g@example.com", picture: "https://x/p.png" });
    const facebook = mapUserInfo("facebook", { id: "f1", name: "F User", picture: { data: { url: "https://x/f.png" } } });
    expect(facebook).toMatchObject({ id: "f1", picture: "https://x/f.png" });
    const discord = mapUserInfo("discord", { id: "d1", username: "duser", avatar: "hash" });
    expect(discord.picture).toBe("https://cdn.discordapp.com/avatars/d1/hash.png");
    const github = mapUserInfo("github", { id: 7, login: "ghuser", avatar_url: "https://x/gh.png" });
    expect(github).toMatchObject({ id: "7", name: "ghuser", picture: "https://x/gh.png" });
    const x = mapUserInfo("x", { data: { id: "x1", name: "X User", username: "xuser" } });
    expect(x).toMatchObject({ id: "x1", name: "X User" });
    expect(() => mapUserInfo("mock", {})).toThrow();
  });
});
