import { base64urlEncode } from "../src/base64";
import type { Jwk } from "../src/jwks";
import type { PendingAuthorize } from "../src/host";
import { expect, open, test } from "nsh/test";
import type { App, HostMessage, StubRequest, StubResponse } from "nsh/test";

const MOCK = "http://127.0.0.1:8755";
const BROKER = "https://broker.nsh-auth-sandbox.example";
const CLIENT_ID = "nsh-auth-sandbox.apps.googleusercontent.com";
const REDIRECT = "nsh.auth.sandbox://callback";
// The native SDK legs' endpoints: the real provider URLs, stubbed here like
// every other host in the harness (no real network).
const GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs";
const APPLE_JWKS = "https://appleid.apple.com/auth/keys";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo";
const FACEBOOK_ME = "https://graph.facebook.com/me?fields=id,name,email,picture";
// The id tokens of the native legs are issued for these, not for CLIENT_ID:
// google's Credential Manager sets the web (server) client id, Apple the bundle id.
const GOOGLE_WEB_AUDIENCE = "nsh-auth-sandbox-web.apps.googleusercontent.com";
const APPLE_BUNDLE_ID = "dev.nshauth.sandbox";
const SESSION_KEY = "nsh-auth:session";
const EVIDENCE = "/Users/hmziq/fo/nsh-auth/docs/evidence/ts-core";
const PROVIDERS = ["google", "facebook", "discord", "github", "apple", "microsoft", "x", "oidc", "mock"] as const;
type ProviderName = (typeof PROVIDERS)[number];

// Pinned per provider, independently of src/providers.ts: the tests hold the
// contract documented in fixtures/provider-catalog.json and docs/providers.md.
const EXPECTED: Record<
  ProviderName,
  { base: string; scopes: string[]; nonce: boolean; pkce: boolean; responseMode?: string; extras?: Record<string, string> }
> = {
  google: {
    base: "https://accounts.google.com/o/oauth2/v2/auth",
    scopes: ["openid", "profile", "email"],
    nonce: true,
    pkce: true,
    extras: { access_type: "offline", prompt: "consent" },
  },
  facebook: { base: "https://www.facebook.com/v27.0/dialog/oauth", scopes: ["openid", "public_profile", "email"], nonce: true, pkce: true },
  discord: { base: "https://discord.com/oauth2/authorize", scopes: ["identify", "email"], nonce: false, pkce: true },
  github: { base: "https://github.com/login/oauth/authorize", scopes: ["read:user", "user:email", "offline_access"], nonce: false, pkce: true },
  apple: { base: "https://appleid.apple.com/auth/authorize", scopes: ["openid", "name", "email"], nonce: true, pkce: false, responseMode: "form_post" },
  microsoft: {
    base: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    scopes: ["openid", "profile", "email", "offline_access", "User.Read"],
    nonce: true,
    pkce: true,
  },
  x: { base: "https://x.com/i/oauth2/authorize", scopes: ["users.read", "tweet.read", "offline.access"], nonce: false, pkce: true },
  oidc: { base: `${MOCK}/oidc/authorize`, scopes: ["openid", "profile", "email", "offline_access"], nonce: true, pkce: true },
  mock: { base: `${MOCK}/mock/authorize`, scopes: ["openid", "profile", "email", "offline_access"], nonce: true, pkce: true },
};

interface Keys {
  privateJwk: Jwk;
  publicJwk: Jwk;
  sign(input: Uint8Array): Promise<ArrayBuffer>;
}

let keysPromise: Promise<Keys> | null = null;

function rsaKeys(): Promise<Keys> {
  keysPromise ??= (async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ["sign", "verify"],
    );
    return {
      privateJwk: await crypto.subtle.exportKey("jwk", pair.privateKey),
      publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
      sign: (input: Uint8Array) => crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, input),
    };
  })();
  return keysPromise;
}

// The mock's scripted answers; each test sets what its scenario needs before the loop runs.
const scenario = {
  nonce: "",
  code: "sandbox-code",
  expiredCode: false,
  refreshRevoked: false,
  refreshRotates: true,
  refreshNetworkError: false,
  refreshServerError: false,
  refreshDelay: 0,
  exchangeDelay: 0,
  reset(): void {
    this.nonce = "";
    this.code = "sandbox-code";
    this.expiredCode = false;
    this.refreshRevoked = false;
    this.refreshRotates = true;
    this.refreshNetworkError = false;
    this.refreshServerError = false;
    this.refreshDelay = 0;
    this.exchangeDelay = 0;
  },
};

async function signIdToken(keys: Keys, claims: Record<string, unknown>): Promise<string> {
  const encoder = new TextEncoder();
  const part = (value: unknown) => base64urlEncode(encoder.encode(JSON.stringify(value)));
  const input = `${part({ alg: "RS256", kid: "sandbox-key", typ: "JWT" })}.${part(claims)}`;
  const signature = await keys.sign(encoder.encode(input));
  return `${input}.${base64urlEncode(new Uint8Array(signature))}`;
}

function tokenAnswer(keys: Keys, request: StubRequest): StubResponse | Promise<StubResponse> {
  const form = new URLSearchParams(request.body ?? "");
  if (form.get("grant_type") === "refresh_token") {
    if (scenario.refreshRevoked) {
      return { status: 400, body: { error: "invalid_grant", error_description: "the refresh token was revoked" } };
    }
    if (scenario.refreshNetworkError) {
      return { error: "connection reset by the stub network" };
    }
    if (scenario.refreshServerError) {
      return { status: 502, body: { error: "server_error", error_description: "token endpoint upstream down" } };
    }
    return {
      body: {
        access_token: "refreshed-token",
        // RFC 6749 §6: a provider may rotate refresh tokens or leave them out.
        ...(scenario.refreshRotates ? { refresh_token: "rotated-refresh" } : {}),
        expires_in: 3600,
        scope: "openid profile email offline_access",
      },
      delay: scenario.refreshDelay,
    };
  }
  if (scenario.expiredCode) {
    return { status: 400, body: { error: "invalid_grant", error_description: "authorization code has expired" } };
  }
  return (async () => ({
    body: {
      access_token: "mock-access",
      refresh_token: "mock-refresh",
      id_token: await signIdToken(keys, {
        iss: `${MOCK}/mock`,
        sub: "user-1",
        aud: CLIENT_ID,
        name: "Sandbox User",
        email: "sandbox@example.com",
        picture: `${MOCK}/avatar.png`,
        exp: 3600,
        nonce: scenario.nonce,
      }),
      expires_in: 3600,
      scope: "openid profile email offline_access",
    },
    delay: scenario.exchangeDelay,
  }))();
}

function mockRoutes(keys: Keys): Record<string, StubResponse | ((request: StubRequest) => StubResponse | Promise<StubResponse>)> {
  return {
    [`POST ${MOCK}/mock/token`]: (request) => tokenAnswer(keys, request),
    [`GET ${MOCK}/mock/userinfo`]: {
      body: { sub: "user-1", name: "Sandbox User", email: "sandbox@example.com", picture: `${MOCK}/avatar.png` },
    },
    [`GET ${MOCK}/mock/.well-known/jwks.json`]: {
      body: { keys: [{ ...keys.publicJwk, kid: "sandbox-key", alg: "RS256", use: "sig" }] },
    },
    [`POST ${MOCK}/mock/revoke`]: { body: {} },
  };
}

interface HostHandlers {
  onAuthorize: (url: string) => string;
  store: Map<string, unknown>;
  /** The host's parked authorize record, exactly as the Android host seals it; {} is its nothing-parked answer. */
  pending?: PendingAuthorize | Record<string, never> | null;
  /** The fake `auth.nativeSignIn` handler. Left out: the embedder handles no such name, which is the channel-absence scenario. Throwing rejects the call the way a real host rejects a dismissed sheet ("cancelled") or a failed SDK call. */
  nativeSignIn?: (request: NativeSignInRequest) => unknown;
}

/** What the core sends over `auth.nativeSignIn`, per the pinned channel contract. */
interface NativeSignInRequest {
  provider?: string;
  nonce?: string;
}

function hostOptions(handlers: HostHandlers) {
  const nativeSignInHandler = handlers.nativeSignIn;
  return {
    handlers: {
      "auth.authorize": async ({ url }: { url: string }) => ({ callbackUrl: handlers.onAuthorize(url) }),
      // Verbatim passthrough: the fake stores exactly what save gives it and
      // returns exactly that on load, so the string contract is exercised by
      // the production save/load, not by the fake.
      "auth.store.save": async ({ key, value }: { key: string; value: unknown }) => {
        handlers.store.set(key, value);
        return null;
      },
      "auth.store.load": async ({ key }: { key: string }) => ({ value: handlers.store.get(key) ?? null }),
      "auth.store.clear": async ({ key }: { key: string }) => {
        handlers.store.delete(key);
        return null;
      },
      // The parked-flow channel: a read reports the record, {clear} consumes it.
      "auth.pendingAuthorize": async ({ clear }: { clear?: boolean }) => {
        if (clear) {
          handlers.pending = null;
          return null;
        }
        return handlers.pending ?? null;
      },
      ...(nativeSignInHandler
        ? {
            "auth.nativeSignIn": async (request: NativeSignInRequest) => {
              nativeRequests.push(request);
              return await nativeSignInHandler(request);
            },
          }
        : {}),
    },
  };
}

// Every auth.nativeSignIn request the fake host received, across the current app.
const nativeRequests: NativeSignInRequest[] = [];

// The exact authorize URL the app must send, built the same way the provider sees it.
function expectedAuthorizeUrl(
  provider: ProviderName,
  values: { state: string; nonce?: string; challenge?: string },
): string {
  const spec = EXPECTED[provider];
  const params = new URLSearchParams();
  params.set("response_type", "code");
  params.set("client_id", CLIENT_ID);
  params.set("redirect_uri", REDIRECT);
  params.set("scope", spec.scopes.join(" "));
  params.set("state", values.state);
  if (spec.nonce && values.nonce) params.set("nonce", values.nonce);
  if (spec.responseMode) params.set("response_mode", spec.responseMode);
  if (spec.pkce && values.challenge) {
    params.set("code_challenge", values.challenge);
    params.set("code_challenge_method", "S256");
  }
  for (const [key, value] of Object.entries(spec.extras ?? {})) params.set(key, value);
  return `${spec.base}?${params.toString()}`;
}

// Same URL with stand-ins for the random values, escaped, as an anchored pattern.
function authorizePattern(provider: ProviderName): RegExp {
  const spec = EXPECTED[provider];
  const template = expectedAuthorizeUrl(provider, { state: "STATE22", nonce: spec.nonce ? "NONCE22" : undefined, challenge: spec.pkce ? "CHALLENGE43" : undefined });
  const escaped = template.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = escaped
    .replaceAll("CHALLENGE43", "[A-Za-z0-9_-]{43}")
    .replaceAll("STATE22", "[A-Za-z0-9_-]{22}")
    .replaceAll("NONCE22", "[A-Za-z0-9_-]{22}");
  return new RegExp(`^${pattern}$`);
}

function authorizeParts(url: string): { state: string; nonce: string | null; challenge: string } {
  const params = new URL(url).searchParams;
  return { state: params.get("state") ?? "", nonce: params.get("nonce"), challenge: params.get("code_challenge") ?? "" };
}

async function challengeOf(verifier: string): Promise<string> {
  return base64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}

// Hex SHA-256 computed independently of the core's own helper, so the Apple
// nonce rule is pinned from the outside.
async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Saves a state's pixels on a real target; a headless run draws nothing, so it skips.
async function shot(app: App, name: string): Promise<void> {
  try {
    await app.screenshot(`${EVIDENCE}/${name}.png`);
  } catch {
    // headless has no pixels
  }
}

// Signs in through the fallback launcher: paste the callback the provider would have sent.
async function signedInWithMock(keys: Keys): Promise<App> {
  scenario.reset();
  const app = await open("../App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  const parts = authorizeParts(app.openedUrls()[0] ?? "");
  scenario.nonce = parts.nonce ?? "";
  await app.type("id:callback-url", `nsh.auth.sandbox://callback?code=${scenario.code}&state=${parts.state}`);
  await app.press("id:submit-callback");
  await app.waitFor("text:status authenticated");
  return app;
}

test("each provider's authorize URL carries pkce, state, scopes and the redirect", async () => {
  const app = await open("../App.tsx", { clock: { time: 0 } });
  await app.waitFor("id:sign-in-google");
  expect(app.shows("text:status idle")).toBe(true);
  await shot(app, "01-idle");
  for (const provider of PROVIDERS) {
    await app.press(`id:sign-in-${provider}`);
  }
  const urls = app.openedUrls();
  expect(urls).toHaveLength(PROVIDERS.length);
  PROVIDERS.forEach((provider, index) => {
    const url = urls[index] ?? "";
    expect(url).toMatch(authorizePattern(provider));
    const spec = EXPECTED[provider];
    const params = new URL(url).searchParams;
    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("redirect_uri")).toBe(REDIRECT);
    expect(params.get("scope")).toBe(spec.scopes.join(" "));
    if (spec.pkce) {
      expect(params.get("code_challenge_method")).toBe("S256");
      expect(params.get("code_challenge")).toHaveLength(43);
    } else {
      expect(params.get("code_challenge_method")).toBeNull();
      expect(params.get("code_challenge")).toBeNull();
    }
    for (const [key, value] of Object.entries(spec.extras ?? {})) expect(params.get(key)).toBe(value);
    const parts = authorizeParts(url);
    expect(parts.state).not.toBe(parts.nonce);
    expect(url).toBe(
      expectedAuthorizeUrl(provider, {
        state: parts.state,
        nonce: parts.nonce ?? undefined,
        challenge: spec.pkce ? parts.challenge : undefined,
      }),
    );
  });
  await shot(app, "02-authorize-urls");
});

test("mock sign-in completes the loop and lands on the session screen", async () => {
  const keys = await rsaKeys();
  const app = await open("../App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.waitFor("text:status authorizing");
  const url = app.openedUrls()[0] ?? "";
  expect(url).toMatch(authorizePattern("mock"));
  const parts = authorizeParts(url);
  expect(url).toBe(expectedAuthorizeUrl("mock", { state: parts.state, nonce: parts.nonce ?? undefined, challenge: parts.challenge }));
  scenario.nonce = parts.nonce ?? "";
  await app.type("id:callback-url", `nsh.auth.sandbox://callback?code=${scenario.code}&state=${parts.state}`);
  await app.press("id:submit-callback");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider mock")).toBe(true);
  expect(app.shows("text:user Sandbox User")).toBe(true);
  expect(app.shows("text:scope openid profile email offline_access")).toBe(true);
  expect(app.shows("text:expires 3600000")).toBe(true);
  const tokenRequest = app.requests().find((request) => request.method === "POST" && request.url === `${MOCK}/mock/token`);
  const form = new URLSearchParams(tokenRequest?.body ?? "");
  expect(form.get("grant_type")).toBe("authorization_code");
  expect(form.get("code")).toBe("sandbox-code");
  expect(form.get("client_id")).toBe(CLIENT_ID);
  expect(form.get("redirect_uri")).toBe(REDIRECT);
  expect(form.get("code_verifier")).toHaveLength(43);
  expect(await challengeOf(form.get("code_verifier") ?? "")).toBe(parts.challenge);
  expect(app.requests().some((request) => request.method === "GET" && request.url === `${MOCK}/mock/userinfo`)).toBe(true);
  expect(app.shows("id:sign-out")).toBe(true);
  await shot(app, "03-authenticated");
});

test("a denial at the provider lands in error, not a session", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await open("../App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  const state = authorizeParts(app.openedUrls()[0] ?? "").state;
  await app.type("id:callback-url", `nsh.auth.sandbox://callback?error=access_denied&error_description=User+denied&state=${state}`);
  await app.press("id:submit-callback");
  await app.waitFor("text:error access_denied");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  expect(app.requests().some((request) => request.url === `${MOCK}/mock/token`)).toBe(false);
  await shot(app, "04-access-denied");
});

test("a callback whose state does not match is refused", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await open("../App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.type("id:callback-url", "nsh.auth.sandbox://callback?code=sandbox-code&state=forged-by-an-attacker");
  await app.press("id:submit-callback");
  await app.waitFor("text:error state_mismatch");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.requests().some((request) => request.url === `${MOCK}/mock/token`)).toBe(false);
  await shot(app, "05-state-mismatch");
});

test("a callback without a state parameter is rejected as state_mismatch", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await open("../App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  // A forged intent can carry a code with no state: the core must not treat absence as a pass.
  await app.type("id:callback-url", "nsh.auth.sandbox://callback?code=sandbox-code");
  await app.press("id:submit-callback");
  await app.waitFor("text:error state_mismatch");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  expect(app.requests().some((request) => request.url === `${MOCK}/mock/token`)).toBe(false);
  await shot(app, "05b-state-missing");
});

test("an id token with a foreign nonce does not sign anyone in", async () => {
  const keys = await rsaKeys();
  const app = await open("../App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  const parts = authorizeParts(app.openedUrls()[0] ?? "");
  scenario.nonce = "nonce-replayed-from-elsewhere";
  await app.type("id:callback-url", `nsh.auth.sandbox://callback?code=${scenario.code}&state=${parts.state}`);
  await app.press("id:submit-callback");
  await app.waitFor("text:error nonce_mismatch");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  await shot(app, "06-nonce-mismatch");
});

test("an expired code is reported as expired, not as a session", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  scenario.expiredCode = true;
  const app = await open("../App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  const state = authorizeParts(app.openedUrls()[0] ?? "").state;
  await app.type("id:callback-url", `nsh.auth.sandbox://callback?code=${scenario.code}&state=${state}`);
  await app.press("id:submit-callback");
  await app.waitFor("text:error expired_code");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  await shot(app, "07-expired-code");
});

test("eight parallel refreshes share one token request", async () => {
  const keys = await rsaKeys();
  const app = await signedInWithMock(keys);
  await app.clock!.runFor(60_000);
  await app.press("id:refresh-8");
  await app.waitFor("text:expires 3660000");
  const refreshes = app
    .requests()
    .filter((request) => request.method === "POST" && request.url === `${MOCK}/mock/token` && (request.body ?? "").includes("grant_type=refresh_token"));
  expect(refreshes).toHaveLength(1);
  expect(new URLSearchParams(refreshes[0]?.body ?? "").get("refresh_token")).toBe("mock-refresh");
  expect(app.shows("text:status authenticated")).toBe(true);
  await shot(app, "08-refreshed");
});

test("a revoked refresh token drops the session", async () => {
  const keys = await rsaKeys();
  const app = await signedInWithMock(keys);
  scenario.refreshRevoked = true;
  await app.press("id:refresh");
  await app.waitFor("text:error invalid_grant");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  await shot(app, "09-revoked-refresh");
});

test("a rotation response without a refresh token keeps the previous one", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => {
        scenario.nonce = authorizeParts(url).nonce ?? "";
        return `nsh.auth.sandbox://callback?code=host-code&state=${authorizeParts(url).state}`;
      },
    }),
  });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.waitFor("text:status authenticated");
  // RFC 6749 §6: the server may change the refresh token or leave it out;
  // a response without one must not erase the token we still hold.
  scenario.refreshRotates = false;
  await app.clock!.runFor(60_000);
  await app.press("id:refresh");
  await app.waitFor("text:status authenticated");
  const refreshes = app
    .requests()
    .filter((request) => request.method === "POST" && request.url === `${MOCK}/mock/token` && (request.body ?? "").includes("grant_type=refresh_token"));
  expect(refreshes).toHaveLength(1);
  const stored = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "{}") as { refreshToken?: string };
  expect(stored.refreshToken).toBe("mock-refresh");
});

test("sign-out revokes the token and clears the session", async () => {
  const keys = await rsaKeys();
  const app = await signedInWithMock(keys);
  await app.press("id:sign-out");
  await app.waitFor("text:status idle");
  expect(app.shows("id:sign-in-mock")).toBe(true);
  const revoke = app.requests().find((request) => request.method === "POST" && request.url === `${MOCK}/mock/revoke`);
  expect(new URLSearchParams(revoke?.body ?? "").get("token")).toBe("mock-refresh");
  await shot(app, "10-signed-out");
});

test("a transient refresh failure leaves the session for retry", async () => {
  const keys = await rsaKeys();
  const app = await signedInWithMock(keys);
  scenario.refreshNetworkError = true;
  await app.press("id:refresh");
  await app.waitFor("text:error network");
  expect(app.shows("text:status error")).toBe(true);
  // The network died, not the grant: the session survives untouched.
  expect(app.shows("text:provider mock")).toBe(true);
  expect(app.shows("id:refresh")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(false);
  // The same grant succeeds once the transport is back.
  scenario.refreshNetworkError = false;
  await app.press("id:refresh");
  await app.waitFor("text:status authenticated");
});

test("a 5xx from the token endpoint is a retryable server_error and keeps the session", async () => {
  const keys = await rsaKeys();
  const app = await signedInWithMock(keys);
  scenario.refreshServerError = true;
  await app.press("id:refresh");
  await app.waitFor("text:error server_error");
  expect(app.shows("text:provider mock")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(false);
  scenario.refreshServerError = false;
  await app.press("id:refresh");
  await app.waitFor("text:status authenticated");
});

test("a sign-out during an in-flight refresh does not resurrect the session", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => {
        scenario.nonce = authorizeParts(url).nonce ?? "";
        return `nsh.auth.sandbox://callback?code=host-code&state=${authorizeParts(url).state}`;
      },
    }),
  });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.waitFor("text:status authenticated");
  scenario.refreshDelay = 5000;
  await app.press("id:refresh");
  await app.waitFor("text:status refreshing");
  await app.press("id:sign-out");
  await app.waitFor("text:status idle");
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  await app.clock!.runFor(6000);
  // The rotated token arrived after sign-out: it must stay abandoned, not saved or applied.
  expect(app.shows("text:status idle")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  await shot(app, "14-signout-during-refresh");
});

test("a sign-out during the code exchange does not resurrect the session", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  scenario.exchangeDelay = 5000;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => {
        scenario.nonce = authorizeParts(url).nonce ?? "";
        return `nsh.auth.sandbox://callback?code=host-code&state=${authorizeParts(url).state}`;
      },
    }),
  });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.waitFor("text:status exchanging");
  await app.press("id:sign-out-anytime");
  await app.waitFor("text:status idle");
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  await app.clock!.runFor(6000);
  // The fresh session arrived after sign-out: it must stay abandoned, not saved or applied.
  expect(app.shows("text:status idle")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  await shot(app, "16-signout-during-exchange");
});

test("a host drives the authorize surface and keeps the session in its secure store", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => {
        scenario.nonce = authorizeParts(url).nonce ?? "";
        return `nsh.auth.sandbox://callback?code=host-code&state=${authorizeParts(url).state}`;
      },
    }),
  });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.waitFor("text:status authenticated");
  const call = app.host.calls().find((entry) => entry.name === "auth.authorize");
  const data = (call?.data ?? {}) as { url?: string; scheme?: string; verifier?: string; state?: string; provider?: string };
  expect(data.scheme).toBe("nsh.auth.sandbox");
  expect(data.url ?? "").toMatch(authorizePattern("mock"));
  // The host seals these into its parked record, so a process death can
  // finish the flow: the callback's state and the exchange's verifier.
  expect(data.provider).toBe("mock");
  expect(data.state).toBe(authorizeParts(data.url ?? "").state);
  expect(data.verifier).toHaveLength(43);
  // The Android host requires the stored value to be a JSON string (requireString).
  expect(typeof hostStore.get(SESSION_KEY)).toBe("string");
  const saved = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "null") as { accessToken?: string };
  expect(saved.accessToken).toBe("mock-access");
  await app.press("id:sign-out");
  await app.waitFor("text:status idle");
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  await shot(app, "11-host-loop");
});

test("a stale host callback from a superseded sign-in is dropped and the active sign-in still completes", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const hostStore = new Map<string, unknown>();
  let authorizeCalls = 0;
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: {
      // Gap 0: both sign-ins start at boot, B superseding A while A's host
      // call is still parked below. The app's JS is suspended while a host
      // call is out, so a boot race is the only way to get one in flight.
      params: { autoSignIn: ["mock", "mock"] },
      handlers: {
        ...hostOptions({ store: hostStore, onAuthorize: (url) => url }).handlers,
        "auth.authorize": async ({ url }: { url: string }) => {
          authorizeCalls += 1;
          scenario.nonce = authorizeParts(url).nonce ?? "";
          const answer = { callbackUrl: `nsh.auth.sandbox://callback?code=host-code&state=${authorizeParts(url).state}` };
          // The runner answers host handlers one at a time, so holding the
          // first answer also holds the second authorize; the hold is in real
          // time because handlers get no clock-coupled delay from the runner.
          if (authorizeCalls === 1) await new Promise((resolve) => setTimeout(resolve, 2500));
          return answer;
        },
      },
    },
  });
  await app.waitFor("text:status authorizing");
  await app.waitFor("text:status authenticated", { timeout: 15000 });
  // The late callback belonged to the superseded flow: dropped, not judged against the active one.
  expect(app.shows("text:status authenticated")).toBe(true);
  expect(app.shows("text:error state_mismatch")).toBe(false);
  expect(app.shows("text:provider mock")).toBe(true);
  await shot(app, "15-stale-callback");
});

test("github's exchange goes through the broker and never carries a secret", async () => {
  const brokerRequests: StubRequest[] = [];
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`POST ${BROKER}/token`]: (request) => {
        brokerRequests.push(request);
        return { body: { accessToken: "broker-access", refreshToken: "broker-refresh", expiresIn: 3600, scope: "read:user user:email" } };
      },
      [`GET https://api.github.com/user`]: {
        body: { id: 1, login: "sandbox-user", name: "Sandbox User", email: "sandbox@example.com", avatar_url: `${BROKER}/avatar.png` },
      },
    },
    host: {
      params: { brokerUrl: BROKER },
      ...hostOptions({
        store: new Map(),
        onAuthorize: (url) => `nsh.auth.sandbox://callback?code=broker-code&state=${authorizeParts(url).state}`,
      }),
    },
  });
  await app.waitFor("id:sign-in-github");
  await app.press("id:sign-in-github");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider github")).toBe(true);
  expect(app.shows("text:user Sandbox User")).toBe(true);
  expect(brokerRequests).toHaveLength(1);
  const exchange = brokerRequests[0] ?? { body: "{}" };
  const payload = JSON.parse(exchange.body ?? "{}") as Record<string, unknown>;
  expect(payload.provider).toBe("github");
  expect(payload.redirectUri).toBe(REDIRECT);
  expect(payload.codeVerifier).toHaveLength(43);
  expect(exchange.headers["accept"]).toBe("application/json");
  expect(exchange.body ?? "").not.toContain("client_secret");
  // The userinfo call is fine; the secret-bearing token endpoint must never be hit from the app.
  expect(app.requests().some((request) => request.url === "https://github.com/login/oauth/access_token")).toBe(false);
  await shot(app, "12-broker");
});

test("a session in the host's store restores on the next start", async () => {
  // Seeded exactly as the real host keeps it: a JSON string under the key,
  // so the restore exercises serialize → string → parse.
  const hostStore = new Map<string, unknown>([
    [
      SESSION_KEY,
      JSON.stringify({ provider: "mock", accessToken: "restored-access", refreshToken: "restored-refresh", expiresAt: 3_600_000, scope: "openid profile email offline_access" }),
    ],
  ]);
  const app = await open("../App.tsx", { clock: { time: 0 }, host: hostOptions({ store: hostStore, onAuthorize: (url) => url }) });
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider mock")).toBe(true);
  expect(app.shows("text:expires 3600000")).toBe(true);
  expect(app.shows("id:sign-out")).toBe(true);
  await shot(app, "13-restored");
});

test("a session expiring within the tolerance margin counts as expired at restore", async () => {
  // 30 seconds left on the token: inside the 60-second proactive margin, so
  // the core refuses to pass it off as a live session and clears the store.
  const hostStore = new Map<string, unknown>([
    [
      SESSION_KEY,
      JSON.stringify({ provider: "mock", accessToken: "dying-access", refreshToken: "dying-refresh", expiresAt: 30_000, scope: "openid profile email offline_access" }),
    ],
  ]);
  const app = await open("../App.tsx", { clock: { time: 0 }, host: hostOptions({ store: hostStore, onAuthorize: (url) => url }) });
  await app.waitFor("id:sign-in-mock");
  expect(app.shows("text:status authenticated")).toBe(false);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  await app.waitUntil(() => !hostStore.has(SESSION_KEY));
});

// The parked record mirrors what the Android host seals: the authorize URL it
// sent, the state and verifier that bind the callback, no tokens.
function parkedRecord(overrides: Partial<PendingAuthorize>): PendingAuthorize {
  const state = "s".repeat(22);
  return {
    scheme: "nsh.auth.sandbox",
    url: expectedAuthorizeUrl("mock", { state, nonce: "n".repeat(22), challenge: "c".repeat(43) }),
    state,
    provider: "mock",
    verifier: "v".repeat(43),
    ...overrides,
  };
}

test("a parked authorize whose redirect already arrived completes the loop at boot", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const record = parkedRecord({});
  scenario.nonce = "n".repeat(22);
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => url,
      pending: { ...record, callbackUrl: `nsh.auth.sandbox://callback?code=parked-code&state=${record.state}` },
    }),
  });
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider mock")).toBe(true);
  expect(app.shows("text:user Sandbox User")).toBe(true);
  const exchange = app.requests().find((request) => request.method === "POST" && request.url === `${MOCK}/mock/token`);
  const form = new URLSearchParams(exchange?.body ?? "");
  expect(form.get("grant_type")).toBe("authorization_code");
  expect(form.get("code")).toBe("parked-code");
  expect(form.get("code_verifier")).toBe("v".repeat(43));
  expect(form.get("redirect_uri")).toBe(REDIRECT);
  expect(form.get("client_id")).toBe(CLIENT_ID);
  const saved = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "{}") as { accessToken?: string };
  expect(saved.accessToken).toBe("mock-access");
  // The consumed record is cleared so a later boot cannot re-run the flow.
  const clears = app.host.calls().filter((entry) => entry.name === "auth.pendingAuthorize" && (entry.data as { clear?: boolean }).clear === true);
  expect(clears).toHaveLength(1);
});

test("a parked authorize with no redirect yet surfaces the interruption honestly", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({ store: new Map(), onAuthorize: (url) => url, pending: parkedRecord({}) }),
  });
  await app.waitFor("text:error interrupted");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-mock")).toBe(true);
  // No browser re-launches without a user action, and no grant is spent.
  expect(app.openedUrls()).toHaveLength(0);
  expect(app.requests().some((request) => request.url === `${MOCK}/mock/token`)).toBe(false);
  // The record stays parked: its redirect may still arrive on a later boot,
  // and a new sign-in supersedes it host-side.
  const clears = app.host.calls().filter((entry) => entry.name === "auth.pendingAuthorize" && (entry.data as { clear?: boolean }).clear === true);
  expect(clears).toHaveLength(0);
});

// A sealed record that cannot answer for its flow fails closed: it must never
// reach the exchange. Each variant is cleared and reported as interrupted.
test("a wantsNonce record whose url carries no nonce is refused, not exchanged", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const state = "s".repeat(22);
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: new Map(),
      onAuthorize: (url) => url,
      pending: {
        ...parkedRecord({}),
        url: expectedAuthorizeUrl("mock", { state, challenge: "c".repeat(43) }),
        callbackUrl: `nsh.auth.sandbox://callback?code=parked-code&state=${state}`,
      },
    }),
  });
  await app.waitFor("text:error interrupted");
  expect(app.requests().some((request) => request.url === `${MOCK}/mock/token`)).toBe(false);
  const clears = app.host.calls().filter((entry) => entry.name === "auth.pendingAuthorize" && (entry.data as { clear?: boolean }).clear === true);
  expect(clears).toHaveLength(1);
});

test("a pkce record without its verifier is refused before the code is spent", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const record = parkedRecord({});
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: new Map(),
      onAuthorize: (url) => url,
      pending: { ...record, verifier: undefined, callbackUrl: `nsh.auth.sandbox://callback?code=parked-code&state=${record.state}` },
    }),
  });
  await app.waitFor("text:error interrupted");
  expect(app.requests().some((request) => request.url === `${MOCK}/mock/token`)).toBe(false);
  const clears = app.host.calls().filter((entry) => entry.name === "auth.pendingAuthorize" && (entry.data as { clear?: boolean }).clear === true);
  expect(clears).toHaveLength(1);
});

test("a record whose sealed url disagrees with its state is refused as unusable", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const record = parkedRecord({});
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({
      store: new Map(),
      onAuthorize: (url) => url,
      pending: {
        ...record,
        url: expectedAuthorizeUrl("mock", { state: "t".repeat(22), nonce: "n".repeat(22), challenge: "c".repeat(43) }),
        callbackUrl: `nsh.auth.sandbox://callback?code=parked-code&state=${record.state}`,
      },
    }),
  });
  await app.waitFor("text:error interrupted");
  expect(app.requests().some((request) => request.url === `${MOCK}/mock/token`)).toBe(false);
  const clears = app.host.calls().filter((entry) => entry.name === "auth.pendingAuthorize" && (entry.data as { clear?: boolean }).clear === true);
  expect(clears).toHaveLength(1);
});

test("a host that replies an empty record boots without the interrupted banner", async () => {
  // Android's auth.pendingAuthorize answers emptyMap() when nothing is
  // parked. The device re-proof caught the core reading that as an unusable
  // record and showing `interrupted` on every boot, over a restored session.
  const keys = await rsaKeys();
  scenario.reset();
  const hostStore = new Map<string, unknown>([
    [
      SESSION_KEY,
      JSON.stringify({ provider: "mock", accessToken: "restored-access", refreshToken: "restored-refresh", expiresAt: 3_600_000, scope: "openid profile email offline_access" }),
    ],
  ]);
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: hostOptions({ store: hostStore, onAuthorize: (url) => url, pending: {} }),
  });
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:error interrupted")).toBe(false);
  expect(app.shows("text:status error")).toBe(false);
  expect(app.shows("text:provider mock")).toBe(true);
  // Nothing parked, so nothing is consumed either.
  const clears = app.host.calls().filter((entry) => entry.name === "auth.pendingAuthorize" && (entry.data as { clear?: boolean }).clear === true);
  expect(clears).toHaveLength(0);
});

test("a host without the pending channel boots and signs in exactly as before", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: mockRoutes(keys),
    host: {
      handlers: {
        "auth.authorize": async ({ url }: { url: string }) => {
          scenario.nonce = authorizeParts(url).nonce ?? "";
          return { callbackUrl: `nsh.auth.sandbox://callback?code=host-code&state=${authorizeParts(url).state}` };
        },
        "auth.store.save": async ({ key, value }: { key: string; value: unknown }) => {
          hostStore.set(key, value);
          return null;
        },
        "auth.store.load": async ({ key }: { key: string }) => ({ value: hostStore.get(key) ?? null }),
        "auth.store.clear": async ({ key }: { key: string }) => {
          hostStore.delete(key);
          return null;
        },
      },
    },
  });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider mock")).toBe(true);
  expect(typeof hostStore.get(SESSION_KEY)).toBe("string");
});

// ---------------------------------------------------------------------------
// Native SDK legs (`auth.nativeSignIn`): the pinned channel contract, the
// per-provider nonce rules, auto-selection and its fallbacks.
// ---------------------------------------------------------------------------

const NATIVE_KEYS = { kid: "sandbox-key", alg: "RS256", use: "sig" };

function authorizeCalls(app: App): HostMessage[] {
  return app.host.calls().filter((entry) => entry.name === "auth.authorize");
}

test("google's iOS native leg exchanges the serverAuthCode directly and lands a session", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`POST ${GOOGLE_TOKEN}`]: {
        body: { access_token: "native-google-access", refresh_token: "native-google-refresh", expires_in: 3600, scope: "openid profile email" },
      },
      [`GET ${GOOGLE_USERINFO}`]: {
        body: { sub: "google-native-user", name: "Google Native", email: "native@example.com", picture: "https://google.example/avatar.png" },
      },
    },
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => url,
      nativeSignIn: () => ({ provider: "google", serverAuthCode: "native-server-code" }),
    }),
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider google")).toBe(true);
  expect(app.shows("text:user Google Native")).toBe(true);
  // The channel call carried the provider and a CSPRNG nonce for the host to bind.
  expect(nativeRequests).toHaveLength(1);
  expect(nativeRequests[0]?.provider).toBe("google");
  expect(nativeRequests[0]?.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
  // Google's token endpoint saw the server code; an SDK leg has no verifier.
  const exchange = app.requests().find((request) => request.method === "POST" && request.url === GOOGLE_TOKEN);
  const form = new URLSearchParams(exchange?.body ?? "");
  expect(form.get("grant_type")).toBe("authorization_code");
  expect(form.get("code")).toBe("native-server-code");
  expect(form.get("client_id")).toBe(CLIENT_ID);
  expect(form.get("redirect_uri")).toBe(REDIRECT);
  expect(form.get("code_verifier")).toBeNull();
  // The native answer finished the flow alone: no browser leg ran.
  expect(authorizeCalls(app)).toHaveLength(0);
  expect(app.openedUrls()).toHaveLength(0);
  const saved = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "{}") as { accessToken?: string; refreshToken?: string; provider?: string };
  expect(saved.provider).toBe("google");
  expect(saved.accessToken).toBe("native-google-access");
  expect(saved.refreshToken).toBe("native-google-refresh");
});

test("google's native serverAuthCode is redeemed through the broker when one is configured", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const brokerRequests: StubRequest[] = [];
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`POST ${BROKER}/token`]: (request) => {
        brokerRequests.push(request);
        return { body: { accessToken: "broker-google-access", refreshToken: "broker-google-refresh", expiresIn: 3600, scope: "openid profile email" } };
      },
      [`GET ${GOOGLE_USERINFO}`]: {
        body: { sub: "google-broker-user", name: "Google Broker", email: "broker@example.com", picture: "https://google.example/avatar.png" },
      },
    },
    host: {
      // The broker is the only holder of the server client's secret, which is
      // what a serverAuthCode is redeemed with.
      params: { brokerUrl: BROKER },
      ...hostOptions({
        store: new Map(),
        onAuthorize: (url) => url,
        nativeSignIn: () => ({ provider: "google", serverAuthCode: "broker-server-code" }),
      }),
    },
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider google")).toBe(true);
  expect(app.shows("text:user Google Broker")).toBe(true);
  expect(brokerRequests).toHaveLength(1);
  const payload = JSON.parse(brokerRequests[0]?.body ?? "{}") as Record<string, unknown>;
  expect(payload.provider).toBe("google");
  expect(payload.code).toBe("broker-server-code");
  expect(payload.redirectUri).toBe(REDIRECT);
  expect(brokerRequests[0]?.body ?? "").not.toContain("client_secret");
  // The direct token endpoint must never see a server code from the app.
  expect(app.requests().some((request) => request.url === GOOGLE_TOKEN)).toBe(false);
  expect(authorizeCalls(app)).toHaveLength(0);
});

test("google's Android native leg verifies the id token for the server audience with the nonce verbatim", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${GOOGLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
    },
    host: {
      params: { nativeAudiences: { google: GOOGLE_WEB_AUDIENCE } },
      ...hostOptions({
        store: hostStore,
        onAuthorize: (url) => url,
        nativeSignIn: async (request) => ({
          provider: "google",
          idToken: await signIdToken(keys, {
            iss: "https://accounts.google.com",
            sub: "android-google-user",
            aud: GOOGLE_WEB_AUDIENCE,
            name: "Android Google",
            email: "android@example.com",
            exp: 3600,
            nonce: request.nonce,
          }),
          nonce: request.nonce,
        }),
      }),
    },
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider google")).toBe(true);
  expect(app.shows("text:user Android Google")).toBe(true);
  // Only the JWKS was fetched: an id-token leg has no token endpoint and no userinfo call.
  expect(app.requests().map((request) => request.url)).toEqual([GOOGLE_JWKS]);
  expect(authorizeCalls(app)).toHaveLength(0);
  // The session stands on the id token: its exp is the expiry and it is the only bearer.
  const saved = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "{}") as { expiresAt?: number; accessToken?: string; idToken?: string; refreshToken?: string };
  expect(saved.expiresAt).toBe(3_600_000);
  expect(typeof saved.idToken).toBe("string");
  expect(saved.accessToken).toBe(saved.idToken);
  expect(saved.refreshToken).toBeUndefined();
});

test("an android google id token with a foreign nonce does not sign anyone in", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${GOOGLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
    },
    host: {
      params: { nativeAudiences: { google: GOOGLE_WEB_AUDIENCE } },
      ...hostOptions({
        store: new Map(),
        onAuthorize: (url) => url,
        nativeSignIn: async (request) => ({
          provider: "google",
          idToken: await signIdToken(keys, {
            iss: "https://accounts.google.com",
            sub: "android-google-user",
            aud: GOOGLE_WEB_AUDIENCE,
            exp: 3600,
            // Replay: the token's binding points somewhere else entirely.
            nonce: "nonce-replayed-from-elsewhere",
          }),
          nonce: request.nonce,
        }),
      }),
    },
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:error nonce_mismatch");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-google")).toBe(true);
  expect(authorizeCalls(app)).toHaveLength(0);
});

test("an android google id token without a configured audience is refused before any fetch", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${GOOGLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
    },
    host: hostOptions({
      store: new Map(),
      onAuthorize: (url) => url,
      nativeSignIn: async (request) => ({
        provider: "google",
        idToken: await signIdToken(keys, {
          iss: "https://accounts.google.com",
          sub: "android-google-user",
          aud: GOOGLE_WEB_AUDIENCE,
          exp: 3600,
          nonce: request.nonce,
        }),
        nonce: request.nonce,
      }),
    }),
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:error unknown");
  expect(app.shows("text:status error")).toBe(true);
  // Fail closed before the network: no key fetch, no browser leg.
  expect(app.requests().map((request) => request.url)).toEqual([]);
  expect(authorizeCalls(app)).toHaveLength(0);
});

test("apple's native leg verifies the identity token against Apple's rules and keeps the authorization code", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${APPLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
    },
    host: {
      params: { nativeAudiences: { apple: APPLE_BUNDLE_ID } },
      ...hostOptions({
        store: hostStore,
        onAuthorize: (url) => url,
        nativeSignIn: async (request) => ({
          provider: "apple",
          identityToken: await signIdToken(keys, {
            iss: "https://appleid.apple.com",
            sub: "apple-native-user",
            aud: APPLE_BUNDLE_ID,
            email: "apple@example.com",
            exp: 3600,
            // Apple's rule: the token's nonce claim is the HASH of the raw nonce.
            nonce: await sha256Hex(request.nonce ?? ""),
          }),
          authorizationCode: "apple-single-use-code",
          nonce: request.nonce,
        }),
      }),
    },
  });
  await app.waitFor("id:sign-in-apple");
  await app.press("id:sign-in-apple");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider apple")).toBe(true);
  expect(app.shows("text:user apple-native-user")).toBe(true);
  expect(app.requests().map((request) => request.url)).toEqual([APPLE_JWKS]);
  expect(authorizeCalls(app)).toHaveLength(0);
  const saved = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "{}") as { authorizationCode?: string; expiresAt?: number; accessToken?: string; idToken?: string };
  // The single-use code is kept on the record for the server (broker) exchange.
  expect(saved.authorizationCode).toBe("apple-single-use-code");
  expect(saved.expiresAt).toBe(3_600_000);
  expect(saved.accessToken).toBe(saved.idToken);
});

test("an apple identity token whose nonce claim is the raw nonce is refused", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${APPLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
    },
    host: {
      params: { nativeAudiences: { apple: APPLE_BUNDLE_ID } },
      ...hostOptions({
        store: new Map(),
        onAuthorize: (url) => url,
        nativeSignIn: async (request) => ({
          provider: "apple",
          identityToken: await signIdToken(keys, {
            iss: "https://appleid.apple.com",
            sub: "apple-native-user",
            aud: APPLE_BUNDLE_ID,
            exp: 3600,
            // The Google rule applied to Apple's token: the raw nonce, unhashed.
            nonce: request.nonce,
          }),
          authorizationCode: "apple-single-use-code",
          nonce: request.nonce,
        }),
      }),
    },
  });
  await app.waitFor("id:sign-in-apple");
  await app.press("id:sign-in-apple");
  await app.waitFor("text:error nonce_mismatch");
  expect(app.shows("text:status error")).toBe(true);
  expect(authorizeCalls(app)).toHaveLength(0);
});

test("an apple result echoing a foreign nonce is refused before any fetch", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${APPLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
    },
    host: {
      params: { nativeAudiences: { apple: APPLE_BUNDLE_ID } },
      ...hostOptions({
        store: new Map(),
        onAuthorize: (url) => url,
        nativeSignIn: async (request) => ({
          provider: "apple",
          identityToken: await signIdToken(keys, {
            iss: "https://appleid.apple.com",
            sub: "apple-native-user",
            aud: APPLE_BUNDLE_ID,
            exp: 3600,
            nonce: await sha256Hex(request.nonce ?? ""),
          }),
          authorizationCode: "apple-single-use-code",
          // The claim is right but the echo lies: fail closed.
          nonce: "a-different-nonce-entirely-xx",
        }),
      }),
    },
  });
  await app.waitFor("id:sign-in-apple");
  await app.press("id:sign-in-apple");
  await app.waitFor("text:error nonce_mismatch");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.requests().map((request) => request.url)).toEqual([]);
  expect(authorizeCalls(app)).toHaveLength(0);
});

test("facebook's native leg wraps the access token and names the user from Graph", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${FACEBOOK_ME}`]: {
        body: { id: "fb-user-1", name: "Facebook Native", email: "fb@example.com", picture: { data: { url: "https://facebook.example/pic.png" } } },
      },
    },
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => url,
      nativeSignIn: () => ({ provider: "facebook", accessToken: "fb-native-token", expiresAt: 86_400_000 }),
    }),
  });
  await app.waitFor("id:sign-in-facebook");
  await app.press("id:sign-in-facebook");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider facebook")).toBe(true);
  expect(app.shows("text:user Facebook Native")).toBe(true);
  expect(app.shows("text:scope openid public_profile email")).toBe(true);
  // Graph /me saw the token as the host handed it over.
  const me = app.requests().find((request) => request.url === FACEBOOK_ME);
  expect(me?.headers["authorization"]).toBe("Bearer fb-native-token");
  expect(authorizeCalls(app)).toHaveLength(0);
  const saved = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "{}") as { accessToken?: string; expiresAt?: number; idToken?: string };
  expect(saved.accessToken).toBe("fb-native-token");
  expect(saved.expiresAt).toBe(86_400_000);
  expect(saved.idToken).toBeUndefined();
});

test("a facebook native token with no host-reported expiry never expires locally", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`GET ${FACEBOOK_ME}`]: { body: { id: "fb-user-1", name: "Facebook Native", email: "fb@example.com" } },
    },
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => url,
      nativeSignIn: () => ({ provider: "facebook", accessToken: "fb-native-token" }),
    }),
  });
  await app.waitFor("id:sign-in-facebook");
  await app.press("id:sign-in-facebook");
  await app.waitFor("text:status authenticated");
  const saved = JSON.parse((hostStore.get(SESSION_KEY) as string) ?? "{}") as { expiresAt?: number };
  expect(saved.expiresAt).toBe(0);
  expect(app.shows("text:status authenticated")).toBe(true);
});

test("cancelling the native sheet leaves the state exactly as it was", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {},
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => url,
      nativeSignIn: () => {
        throw new Error("cancelled");
      },
    }),
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:status idle");
  // No error report, no session, no store write, and no browser leg either.
  expect(app.shows("id:error")).toBe(false);
  expect(app.shows("id:sign-in-google")).toBe(true);
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  expect(app.requests()).toHaveLength(0);
  expect(authorizeCalls(app)).toHaveLength(0);
  expect(app.openedUrls()).toHaveLength(0);
});

test("cancelling a native sign-in over a restored session keeps that session", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>([
    [
      SESSION_KEY,
      JSON.stringify({ provider: "mock", accessToken: "restored-access", refreshToken: "restored-refresh", expiresAt: 3_600_000, scope: "openid profile email offline_access" }),
    ],
  ]);
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {},
    host: {
      params: { autoSignIn: ["google"] },
      ...hostOptions({
        store: hostStore,
        onAuthorize: (url) => url,
        nativeSignIn: () => {
          throw new Error("cancelled");
        },
      }),
    },
  });
  await app.waitFor("text:status authenticated");
  // The native channel was attempted (and its sheet dismissed) before the asserts below.
  await app.waitUntil(() => nativeRequests.length > 0);
  // The cancel restored the sign-in's starting point: the restored session, not an error.
  expect(app.shows("text:provider mock")).toBe(true);
  expect(app.shows("id:error")).toBe(false);
  expect(app.shows("text:status error")).toBe(false);
  expect(hostStore.get(SESSION_KEY)).toBeTruthy();
  expect(authorizeCalls(app)).toHaveLength(0);
});

test("a native SDK failure is an error, not a browser fallback", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {},
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => url,
      nativeSignIn: () => {
        throw new Error("GetCredentialException: 16: the OAuth client was not found");
      },
    }),
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:error unknown");
  expect(app.shows("text:status error")).toBe(true);
  expect(app.shows("id:sign-in-google")).toBe(true);
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  expect(app.requests()).toHaveLength(0);
  expect(authorizeCalls(app)).toHaveLength(0);
  expect(app.openedUrls()).toHaveLength(0);
});

// Android's NativeSignInModule serves only google and facebook; this is its
// unknown-provider rejection verbatim (NativeSignInModule.kt, wrapped in an
// IllegalArgumentException and delivered with code ERR_NSH_HOST_ERROR).
const androidUnknownProvider = (request: NativeSignInRequest): never => {
  throw new Error(`auth.nativeSignIn: unknown provider "${request.provider}" (known: google, facebook)`);
};

test("apple on an android-shaped host falls back to the browser, google stays native", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const brokerBodies: string[] = [];
  let authorizeUrl = "";
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`POST ${BROKER}/token`]: async (request) => {
        brokerBodies.push(request.body ?? "");
        return {
          body: {
            accessToken: "apple-browser-access",
            // The broker signs for Apple's browser flow; the nonce claim must
            // be the one the authorize URL carried or verification refuses.
            idToken: await signIdToken(keys, {
              iss: "https://appleid.apple.com",
              sub: "apple-browser-user",
              aud: CLIENT_ID,
              email: "apple-browser@example.com",
              name: "Apple Browser User",
              exp: 3600,
              nonce: authorizeParts(authorizeUrl).nonce ?? "",
            }),
            expiresIn: 3600,
            scope: "openid name email",
          },
        };
      },
      // signOut of the apple session revokes through the broker too.
      [`POST ${BROKER}/revoke`]: { body: {} },
      [`GET ${APPLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
      [`GET ${GOOGLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
    },
    host: {
      params: { brokerUrl: BROKER, nativeAudiences: { google: GOOGLE_WEB_AUDIENCE } },
      ...hostOptions({
        store: hostStore,
        onAuthorize: (url) => {
          authorizeUrl = url;
          return `nsh.auth.sandbox://callback?code=apple-fallback-code&state=${authorizeParts(url).state}`;
        },
        nativeSignIn: async (request) => {
          if (request.provider === "apple") androidUnknownProvider(request);
          return {
            provider: "google",
            idToken: await signIdToken(keys, {
              iss: "https://accounts.google.com",
              sub: "android-google-user",
              aud: GOOGLE_WEB_AUDIENCE,
              exp: 3600,
              nonce: request.nonce ?? "",
            }),
            nonce: request.nonce,
          };
        },
      }),
    },
  });
  await app.waitFor("id:sign-in-apple");
  await app.press("id:sign-in-apple");
  await app.waitFor("text:status authenticated");
  // The fallback built Apple's real authorize URL (form_post, no PKCE) and
  // completed through the broker; reaching a session proves the id token's
  // nonce claim matched the nonce the core sent, or verification would have
  // refused it.
  expect(authorizeUrl).toMatch(authorizePattern("apple"));
  expect(app.shows("text:provider apple")).toBe(true);
  expect(app.shows("text:user Apple Browser User")).toBe(true);
  expect(nativeRequests.map((request) => request.provider)).toEqual(["apple"]);
  expect(authorizeCalls(app)).toHaveLength(1);
  // Apple has no PKCE and no secret may ride along: the exchange carries the
  // bare code and redirect to the broker.
  const exchange = JSON.parse(brokerBodies[0] ?? "{}") as Record<string, unknown>;
  expect(exchange.provider).toBe("apple");
  expect(exchange.code).toBe("apple-fallback-code");
  expect(exchange.codeVerifier).toBeUndefined();
  expect(brokerBodies[0] ?? "").not.toContain("client_secret");

  // Back to the buttons: the same host still serves google's native leg —
  // the rejection class is per provider, never a whole-channel verdict. The
  // Android id-token path names the user from the token's own claims.
  await app.press("id:sign-out-anytime");
  await app.waitFor("text:status idle");
  await app.press("id:sign-in-google");
  await app.waitFor("text:user android-google-user");
  expect(app.shows("text:provider google")).toBe(true);
  expect(nativeRequests.map((request) => request.provider)).toEqual(["apple", "google"]);
  expect(authorizeCalls(app)).toHaveLength(1);
});

test("a channel-prefixed configuration failure is still an error, not a browser fallback", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {},
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => url,
      // iOS's own prefixed failure shape: the channel answered, the leg is
      // misconfigured — nothing about the provider is absent.
      nativeSignIn: () => {
        throw new Error("auth.nativeSignIn google: GIDClientID missing from Info.plist");
      },
    }),
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:error unknown");
  expect(app.shows("text:status error")).toBe(true);
  expect(hostStore.has(SESSION_KEY)).toBe(false);
  expect(authorizeCalls(app)).toHaveLength(0);
  expect(app.openedUrls()).toHaveLength(0);
});

test("a host whose embedder predates the native channel falls back to the browser loop", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  nativeRequests.length = 0;
  const hostStore = new Map<string, unknown>();
  let fallbackNonce = "";
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {
      [`POST ${GOOGLE_TOKEN}`]: async () => ({
        body: {
          access_token: "fallback-access",
          id_token: await signIdToken(keys, {
            iss: "https://accounts.google.com",
            sub: "fallback-user",
            aud: CLIENT_ID,
            name: "Fallback User",
            exp: 3600,
            nonce: fallbackNonce,
          }),
          expires_in: 3600,
          scope: "openid profile email",
        },
      }),
      [`GET ${GOOGLE_JWKS}`]: { body: { keys: [{ ...keys.publicJwk, ...NATIVE_KEYS }] } },
      [`GET ${GOOGLE_USERINFO}`]: {
        body: { sub: "fallback-user", name: "Fallback User", email: "fallback@example.com", picture: "https://google.example/avatar.png" },
      },
    },
    // No nativeSignIn handler: the engine answers that the embedder handles no
    // such name, and the core must complete the sign-in in the browser.
    host: hostOptions({
      store: hostStore,
      onAuthorize: (url) => {
        fallbackNonce = authorizeParts(url).nonce ?? "";
        return `nsh.auth.sandbox://callback?code=fallback-code&state=${authorizeParts(url).state}`;
      },
    }),
  });
  await app.waitFor("id:sign-in-google");
  await app.press("id:sign-in-google");
  await app.waitFor("text:status authenticated");
  expect(app.shows("text:provider google")).toBe(true);
  expect(app.shows("text:user Fallback User")).toBe(true);
  expect(authorizeCalls(app)).toHaveLength(1);
  expect(authorizeCalls(app)[0]?.name).toBe("auth.authorize");
});

test("an explicit native-only signIn on a host without the channel reports no_launcher", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const app = await open("../App.tsx", {
    clock: { time: 0 },
    network: {},
    host: hostOptions({ store: new Map(), onAuthorize: (url) => url }),
  });
  await app.waitFor("id:sign-in-native-facebook");
  await app.press("id:sign-in-native-facebook");
  await app.waitFor("text:error no_launcher");
  expect(app.shows("text:status error")).toBe(true);
  // Explicit native-only means no silent browser leg.
  expect(authorizeCalls(app)).toHaveLength(0);
  expect(app.openedUrls()).toHaveLength(0);
});

test("an explicit native-only signIn on a hostless surface reports no_launcher", async () => {
  scenario.reset();
  nativeRequests.length = 0;
  const app = await open("../App.tsx", { clock: { time: 0 }, network: {} });
  await app.waitFor("id:sign-in-native-facebook");
  await app.press("id:sign-in-native-facebook");
  await app.waitFor("text:error no_launcher");
  expect(app.shows("text:status error")).toBe(true);
  // No host means no browser fallback either: the caller asked for native only.
  expect(app.openedUrls()).toHaveLength(0);
});
