import { base64urlEncode } from "../src/base64";
import type { Jwk } from "../src/jwks";
import { expect, open, test } from "nsh/test";
import type { App, StubRequest, StubResponse } from "nsh/test";

const MOCK = "http://127.0.0.1:8755";
const BROKER = "https://broker.nsh-auth-sandbox.example";
const CLIENT_ID = "nsh-auth-sandbox.apps.googleusercontent.com";
const REDIRECT = "nsh-auth-demo://callback";
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
  refreshDelay: 0,
  exchangeDelay: 0,
  reset(): void {
    this.nonce = "";
    this.code = "sandbox-code";
    this.expiredCode = false;
    this.refreshRevoked = false;
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
    return {
      body: { access_token: "refreshed-token", refresh_token: "rotated-refresh", expires_in: 3600, scope: "openid profile email offline_access" },
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
}

function hostOptions(handlers: HostHandlers) {
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
    },
  };
}

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
  await app.type("id:callback-url", `nsh-auth-demo://callback?code=${scenario.code}&state=${parts.state}`);
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
  await app.type("id:callback-url", `nsh-auth-demo://callback?code=${scenario.code}&state=${parts.state}`);
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
  await app.type("id:callback-url", `nsh-auth-demo://callback?error=access_denied&error_description=User+denied&state=${state}`);
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
  await app.type("id:callback-url", "nsh-auth-demo://callback?code=sandbox-code&state=forged-by-an-attacker");
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
  await app.type("id:callback-url", "nsh-auth-demo://callback?code=sandbox-code");
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
  await app.type("id:callback-url", `nsh-auth-demo://callback?code=${scenario.code}&state=${parts.state}`);
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
  await app.type("id:callback-url", `nsh-auth-demo://callback?code=${scenario.code}&state=${state}`);
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
        return `nsh-auth-demo://callback?code=host-code&state=${authorizeParts(url).state}`;
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
        return `nsh-auth-demo://callback?code=host-code&state=${authorizeParts(url).state}`;
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
        return `nsh-auth-demo://callback?code=host-code&state=${authorizeParts(url).state}`;
      },
    }),
  });
  await app.waitFor("id:sign-in-mock");
  await app.press("id:sign-in-mock");
  await app.waitFor("text:status authenticated");
  const call = app.host.calls().find((entry) => entry.name === "auth.authorize");
  const data = (call?.data ?? {}) as { url?: string; scheme?: string };
  expect(data.scheme).toBe("nsh-auth-demo");
  expect(data.url ?? "").toMatch(authorizePattern("mock"));
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
          const answer = { callbackUrl: `nsh-auth-demo://callback?code=host-code&state=${authorizeParts(url).state}` };
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
        onAuthorize: (url) => `nsh-auth-demo://callback?code=broker-code&state=${authorizeParts(url).state}`,
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
