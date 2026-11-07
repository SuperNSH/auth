// The full mock loop through the demo's UI. The test file's imports are a
// separate module instance from the running app's (verified by probe on
// 0.4.0), so everything goes through the UI, the stubbed network, and the host
// the test plays: open({ host }) answers auth.authorize/auth.store.*, and
// app.host.send feeds the redirect event where a flow needs it.
import { expect, open, test } from "nsh/test";
import type { App, StubRequest, StubResponse } from "nsh/test";
import { CLIENT_ID, MOCK_BASE_URL, MOCK_BASE_URL_STORAGE_KEY, REDIRECT_URI, SCOPES } from "./src/dev/fixtures";

type Network = NonNullable<NonNullable<Parameters<typeof open>[1]>["network"]>;

const EMULATOR_MOCK = "http://10.0.2.2:8755";
const SESSION_KEY = "nsh-auth:session";

function segment(value: object): string {
  return segmentBytes(new TextEncoder().encode(JSON.stringify(value)));
}

function segmentBytes(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .split("+")
    .join("-")
    .split("/")
    .join("_")
    .split("=")
    .join("");
}

interface Keys {
  publicJwk: Record<string, unknown>;
  sign(input: Uint8Array): Promise<ArrayBuffer>;
}

let keysPromise: Promise<Keys> | null = null;

// One RS256 keypair per run: the stub JWKS publishes its public half and the
// stubbed token endpoint signs id tokens with the private half.
function rsaKeys(): Promise<Keys> {
  keysPromise ??= (async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ["sign", "verify"],
    );
    return {
      publicJwk: (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<string, unknown>,
      sign: (input: Uint8Array) => crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, input),
    };
  })();
  return keysPromise;
}

async function signIdToken(keys: Keys, claims: Record<string, unknown>): Promise<string> {
  const input = `${segment({ alg: "RS256", kid: "sandbox-key", typ: "JWT" })}.${segment(claims)}`;
  const signature = await keys.sign(new TextEncoder().encode(input));
  return `${input}.${segmentBytes(new Uint8Array(signature))}`;
}

// The mock's scripted answers; each test sets what its scenario needs first.
const scenario = {
  nonce: "",
  code: "sandbox-code",
  expiredCode: false,
  refreshRevoked: false,
  reset(): void {
    this.nonce = "";
    this.code = "sandbox-code";
    this.expiredCode = false;
    this.refreshRevoked = false;
  },
};

function tokenAnswer(keys: Keys, request: StubRequest, base = MOCK_BASE_URL): StubResponse | Promise<StubResponse> {
  const form = new URLSearchParams(request.body ?? "");
  if (form.get("grant_type") === "refresh_token") {
    if (scenario.refreshRevoked) {
      return { status: 400, body: { error: "invalid_grant", error_description: "the refresh token was revoked" } };
    }
    return {
      body: { access_token: "at-second", refresh_token: "rt-second", expires_in: 3600, scope: SCOPES.join(" ") },
    };
  }
  if (scenario.expiredCode) {
    // The core maps invalid_grant + an expired description to expired_code.
    return { status: 400, body: { error: "invalid_grant", error_description: "authorization code has expired" } };
  }
  return (async () => ({
    body: {
      access_token: "at-first",
      refresh_token: "rt-first",
      id_token: await signIdToken(keys, {
        iss: `${base}/mock`,
        sub: "user-1",
        aud: CLIENT_ID,
        name: "Sandbox User",
        email: "sandbox@example.com",
        exp: 3600,
        nonce: scenario.nonce,
      }),
      expires_in: 3600,
      scope: SCOPES.join(" "),
    },
  }))();
}

function mockRoutes(keys: Keys, base = MOCK_BASE_URL): Network {
  return {
    [`POST ${base}/mock/token`]: (request) => tokenAnswer(keys, request, base),
    [`GET ${base}/mock/userinfo`]: { body: { sub: "user-1", name: "Sandbox User", email: "sandbox@example.com" } },
    [`GET ${base}/mock/.well-known/jwks.json`]: {
      body: { keys: [{ ...keys.publicJwk, kid: "sandbox-key", alg: "RS256", use: "sig" }] },
    },
    [`POST ${base}/mock/revoke`]: { body: {} },
  };
}

// The test plays the embedding host: it catches the redirect (auth.authorize
// answers {callbackUrl}) and keeps the session in its secure store.
function hostHandlers(onAuthorize: (url: string) => string, store: Map<string, unknown>) {
  return {
    "auth.authorize": async ({ url }: { url: string }) => ({ callbackUrl: onAuthorize(url) }),
    "auth.store.save": async ({ key, value }: { key: string; value: unknown }) => {
      // Real hosts store text (Android's contract); the harness delivers the
      // nested session value the same way, so parse before asserting.
      const parsed = typeof value === "string" ? JSON.parse(value) : value;
      store.set(key, parsed);
      return null;
    },
    "auth.store.load": async ({ key }: { key: string }) => ({ value: store.get(key) ?? null }),
    "auth.store.clear": async ({ key }: { key: string }) => {
      store.delete(key);
      return null;
    },
  };
}

async function openWithHost(
  network: Network,
  extra?: { params?: Record<string, unknown>; onAuthorize?: (url: string) => string; withConfig?: boolean },
  storage?: Record<string, string>,
): Promise<{ app: App; store: Map<string, unknown> }> {
  const store = new Map<string, unknown>();
  const app = await open("./App.tsx", {
    clock: { time: 0 },
    network,
    storage,
    host: {
      params: extra?.params ?? {},
      handlers: {
        ...hostHandlers(extra?.onAuthorize ?? ((url) => url), store),
        ...(extra?.withConfig
          ? {
              "auth.config": async (data: { mockBaseUrl?: string }) => ({
                mockBaseUrl: data?.mockBaseUrl ?? null,
                autoStart: null,
                provider: null,
              }),
            }
          : {}),
      },
    },
  });
  return { app, store };
}

function authorizeParts(url: string): { state: string; nonce: string | null; challenge: string } {
  const params = new URL(url).searchParams;
  return { state: params.get("state") ?? "", nonce: params.get("nonce"), challenge: params.get("code_challenge") ?? "" };
}

// The exact authorize URL the mock provider must see, with the random values filled in.
function expectedMockAuthorizeUrl(values: { state: string; nonce: string; challenge: string }, base = MOCK_BASE_URL): string {
  const params = new URLSearchParams();
  params.set("response_type", "code");
  params.set("client_id", CLIENT_ID);
  params.set("redirect_uri", REDIRECT_URI);
  params.set("scope", SCOPES.join(" "));
  params.set("state", values.state);
  params.set("nonce", values.nonce);
  params.set("code_challenge", values.challenge);
  params.set("code_challenge_method", "S256");
  return `${base}/mock/authorize?${params.toString()}`;
}

async function challengeOf(verifier: string): Promise<string> {
  return segmentBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}

test("mock sign-in: authorize URL, exchange, session screen", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const { app, store } = await openWithHost(mockRoutes(keys), {
    onAuthorize: (url) => {
      scenario.nonce = authorizeParts(url).nonce ?? "";
      return `${REDIRECT_URI}?code=${scenario.code}&state=${authorizeParts(url).state}`;
    },
  });
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");
  await app.waitFor("text:Status: authenticated");

  const call = app.host.calls().find((entry) => entry.name === "auth.authorize");
  expect(call).toBeTruthy();
  const data = (call!.data ?? {}) as { url?: string; scheme?: string };
  expect(data.scheme).toBe("nsh.auth.sandbox");
  const url = data.url ?? "";
  const parts = authorizeParts(url);
  expect(url).toBe(expectedMockAuthorizeUrl({ state: parts.state, nonce: parts.nonce ?? "", challenge: parts.challenge }));

  const exchange = app.requests().find((entry) => entry.method === "POST" && entry.url === `${MOCK_BASE_URL}/mock/token`);
  expect(exchange).toBeTruthy();
  const form = new URLSearchParams(exchange!.body ?? "");
  expect(form.get("grant_type")).toBe("authorization_code");
  expect(form.get("code")).toBe(scenario.code);
  expect(form.get("client_id")).toBe(CLIENT_ID);
  expect(form.get("redirect_uri")).toBe(REDIRECT_URI);
  expect(form.get("code_verifier")).toHaveLength(43);
  expect(await challengeOf(form.get("code_verifier") ?? "")).toBe(parts.challenge);
  expect(app.requests().some((entry) => entry.url === `${MOCK_BASE_URL}/mock/userinfo`)).toBe(true);

  expect(app.shows("text:Sandbox User")).toBe(true);
  expect(app.shows("role:button[Sign out]")).toBe(true);
  expect(app.shows("text:Access token: …irst")).toBe(true);
  expect(app.shows("text:Refresh token: stored")).toBe(true);
  const saved = store.get(SESSION_KEY) as { accessToken?: string } | undefined;
  console.log("STORE-VALUE", JSON.stringify(saved));
  expect(saved?.accessToken).toBe("at-first");
});

test("no host: the authorize URL opens, and the paste-back finishes the loop", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await open("./App.tsx", { clock: { time: 0 }, network: mockRoutes(keys) });
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");

  const urls = app.openedUrls();
  expect(urls).toHaveLength(1);
  const parts = authorizeParts(urls[0] ?? "");
  scenario.nonce = parts.nonce ?? "";
  expect(urls[0]).toBe(expectedMockAuthorizeUrl({ state: parts.state, nonce: parts.nonce ?? "", challenge: parts.challenge }));
  await app.waitFor("text:Waiting for the provider's redirect…");

  await app.type("id:callback-url", `${REDIRECT_URI}?code=${scenario.code}&state=${parts.state}`);
  await app.press("role:button[Finish sign-in]");
  await app.waitFor("text:Status: authenticated");
  expect(app.shows("role:button[Sign out]")).toBe(true);
});

test("a denied authorization shows the access_denied banner", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await openWithHost(mockRoutes(keys), {
    onAuthorize: (url) => `${REDIRECT_URI}?error=access_denied&error_description=User+denied&state=${authorizeParts(url).state}`,
  }).then(({ app }) => app);
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");
  await app.waitFor("text:access_denied");
  expect(app.shows("role:alert")).toBe(true);
  expect(app.shows("role:button[Sign out]")).toBe(false);
  expect(app.requests().some((entry) => entry.url === `${MOCK_BASE_URL}/mock/token`)).toBe(false);
});

test("a callback whose state does not match is refused", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await openWithHost(mockRoutes(keys), {
    onAuthorize: (url) => `${REDIRECT_URI}?code=${scenario.code}&state=forged-by-an-attacker`,
  }).then(({ app }) => app);
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");
  await app.waitFor("text:state_mismatch");
  expect(app.shows("role:button[Sign out]")).toBe(false);
  expect(app.requests().some((entry) => entry.url === `${MOCK_BASE_URL}/mock/token`)).toBe(false);
});

test("an id token with a foreign nonce does not sign anyone in", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await openWithHost(mockRoutes(keys), {
    onAuthorize: (url) => {
      scenario.nonce = "nonce-replayed-from-elsewhere";
      return `${REDIRECT_URI}?code=${scenario.code}&state=${authorizeParts(url).state}`;
    },
  }).then(({ app }) => app);
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");
  await app.waitFor("text:nonce_mismatch");
  expect(app.shows("role:button[Sign out]")).toBe(false);
});

test("an expired code is reported as expired_code, not as a session", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  scenario.expiredCode = true;
  const app = await openWithHost(mockRoutes(keys), {
    onAuthorize: (url) => `${REDIRECT_URI}?code=${scenario.code}&state=${authorizeParts(url).state}`,
  }).then(({ app }) => app);
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");
  await app.waitFor("text:expired_code");
  expect(app.shows("role:button[Sign out]")).toBe(false);
});

test("refresh updates the session and reloads the profile", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await signedInWithHost(keys);
  await app.waitFor("text:Access token: …irst");

  await app.press("role:button[Refresh session]");
  await app.waitFor("text:Access token: …cond");
  expect(app.shows("text:Status: authenticated")).toBe(true);
  // One userinfo GET comes from the package's sign-in flow, one from the
  // profile query's first load, one from its forced refetch at refresh.
  const profileLoads = app.requests().filter((entry) => entry.url === `${MOCK_BASE_URL}/mock/userinfo`);
  expect(profileLoads.length).toBe(3);
});

test("eight parallel refreshes reach the token endpoint once", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await signedInWithHost(keys);
  await app.waitFor("text:Access token: …irst");

  await app.host.send("auth.test.refreshBurst", { count: 8 });
  await app.waitFor("text:Access token: …cond");
  const refreshes = app
    .requests()
    .filter(
      (entry) =>
        entry.method === "POST" &&
        entry.url === `${MOCK_BASE_URL}/mock/token` &&
        (entry.body ?? "").includes("grant_type=refresh_token"),
    );
  expect(refreshes).toHaveLength(1);
  expect(new URLSearchParams(refreshes[0]?.body ?? "").get("refresh_token")).toBe("rt-first");
  expect(app.shows("text:Status: authenticated")).toBe(true);
});

test("a revoked refresh drops the session", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  scenario.refreshRevoked = true;
  const app = await signedInWithHost(keys);
  await app.press("role:button[Refresh session]");
  await app.waitFor("text:invalid_grant");
  await app.waitFor("role:button[Sign in with Mock]");
  expect(app.shows("role:button[Sign out]")).toBe(false);
});

test("sign-out revokes the token and clears the session screen", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await signedInWithHost(keys);
  await app.press("role:button[Sign out]");
  await app.waitFor("role:button[Sign in with Mock]");
  expect(app.shows("role:button[Sign out]")).toBe(false);
  expect(app.shows("text:Status: authenticated")).toBe(false);
  const revoke = app.requests().find((entry) => entry.method === "POST" && entry.url === `${MOCK_BASE_URL}/mock/revoke`);
  expect(new URLSearchParams(revoke?.body ?? "").get("token")).toBe("rt-first");
});

test("the saved contact email shows as the account's contact", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const app = await signedInWithHost(keys, { contact: "user@example.com" });
  await app.waitFor("text:Contact: user@example.com");
});

test("a bare relaunch reuses the persisted mock base", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  // No launch extras and no auth.config answer: only the Storage layer knows
  // the emulator base a previous device-phase run resolved.
  const { app } = await openWithHost(
    mockRoutes(keys, EMULATOR_MOCK),
    {
      onAuthorize: (url) => {
        scenario.nonce = authorizeParts(url).nonce ?? "";
        return `${REDIRECT_URI}?code=${scenario.code}&state=${authorizeParts(url).state}`;
      },
    },
    { [MOCK_BASE_URL_STORAGE_KEY]: EMULATOR_MOCK },
  );
  // A bare relaunch has no autoStart: the user presses the provider button.
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");
  const call = app.host.calls().find((entry) => entry.name === "auth.authorize");
  const url = ((call?.data ?? {}) as { url?: string }).url ?? "";
  expect(`${new URL(url).origin}/mock/authorize`).toBe(`${EMULATOR_MOCK}/mock/authorize`);
  await app.waitFor("text:Status: authenticated");
  const userinfo = app.requests().find((entry) => entry.url === `${EMULATOR_MOCK}/mock/userinfo`);
  expect(userinfo?.url).toBe(`${EMULATOR_MOCK}/mock/userinfo`);
  // The resolved base persists for later bare relaunches (plain Storage).
  expect(app.storage()[MOCK_BASE_URL_STORAGE_KEY]).toBe(EMULATOR_MOCK);
});

test("host params and auth.config drive mockBaseUrl and autoStart", async () => {
  const keys = await rsaKeys();
  scenario.reset();
  const { app } = await openWithHost(mockRoutes(keys, EMULATOR_MOCK), {
    params: { auth: { redirectUri: REDIRECT_URI, mockBaseUrl: EMULATOR_MOCK, autoStart: "mock" } },
    withConfig: true,
    onAuthorize: (url) => {
      scenario.nonce = authorizeParts(url).nonce ?? "";
      return `${REDIRECT_URI}?code=${scenario.code}&state=${authorizeParts(url).state}`;
    },
  });
  await app.waitFor("text:Status: authenticated");
  const call = app.host.calls().find((entry) => entry.name === "auth.authorize");
  const url = ((call?.data ?? {}) as { url?: string }).url ?? "";
  const parts = authorizeParts(url);
  expect(url).toBe(expectedMockAuthorizeUrl({ state: parts.state, nonce: parts.nonce ?? "", challenge: parts.challenge }, EMULATOR_MOCK));
  expect(app.shows("text:Sandbox User")).toBe(true);
  const userinfo = app.requests().find((entry) => entry.url === `${EMULATOR_MOCK}/mock/userinfo`);
  expect(userinfo?.url).toBe(`${EMULATOR_MOCK}/mock/userinfo`);
  // The resolved base persists for later bare relaunches (plain Storage).
  expect(app.storage()[MOCK_BASE_URL_STORAGE_KEY]).toBe(EMULATOR_MOCK);
});

/** Signs in through the embedded host path and lands on the account screen. */
async function signedInWithHost(keys: Keys, options?: { contact?: string }): Promise<App> {
  const { app } = await openWithHost(mockRoutes(keys), {
    onAuthorize: (url) => {
      scenario.nonce = authorizeParts(url).nonce ?? "";
      return `${REDIRECT_URI}?code=${scenario.code}&state=${authorizeParts(url).state}`;
    },
  });
  await app.waitFor("role:button[Sign in with Mock]");
  if (options?.contact) {
    await app.type("id:contact-email", options.contact);
    await app.press("id:save-email");
    await app.waitFor(`text:Saved: ${options.contact}`);
  }
  await app.press("role:button[Sign in with Mock]");
  await app.waitFor("text:Status: authenticated");
  return app;
}
