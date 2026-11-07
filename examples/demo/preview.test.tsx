// Tests for the demo's own UI pieces (providers table, email form, userinfo
// query, claims readout) through the preview entry, with no nsh-auth import:
// they run whether or not the sibling package is complete.
import { expect, open, test } from "nsh/test";
import { claimsToRows } from "./src/ui/claims-table";
import { MOCK_BASE_URL, PREVIEW_CLAIMS, PREVIEW_USERINFO_URL } from "./src/dev/fixtures";

// The preview entry lives at the package root: the theme tokens come from the
// nsh.json next to the entry, so an entry deeper down loses them (0.4.0).
const PREVIEW = "./preview.tsx";

const ALL_LABELS = [
  "Sign in with Google",
  "Continue with Facebook",
  "Continue with Discord",
  "Sign in with GitHub",
  "Sign in with Apple",
  "Sign in with Microsoft",
  "Continue with X",
  "Sign in with OIDC",
  "Sign in with Mock",
];

test("every provider button renders with its label", async () => {
  const app = await open(PREVIEW, { clock: {} });
  await app.waitFor("role:button[Sign in with Mock]");
  for (const label of ALL_LABELS) {
    expect(app.shows(`role:button[${label}]`)).toBe(true);
  }
});

test("pressing a provider button reports which one", async () => {
  const app = await open(PREVIEW, { clock: {} });
  await app.waitFor("role:button[Sign in with Mock]");
  await app.press("role:button[Sign in with Mock]");
  await app.waitFor("text:Pressed: mock");
});

test("the paste-back fallback renders on a hostless surface", async () => {
  const app = await open(PREVIEW, { clock: {} });
  await app.waitFor("id:callback-url");
  expect(app.shows("text:Finish a sign-in by hand")).toBe(true);
  expect(app.enabled("role:button[Finish sign-in]")).toBe(false);
  await app.type("id:callback-url", "nsh.auth.sandbox://callback?code=x&state=y");
  expect(app.enabled("role:button[Finish sign-in]")).toBe(true);
});

test("the contact email form validates before it saves", async () => {
  const app = await open(PREVIEW, { clock: {} });
  await app.waitFor("id:contact-email");

  await app.press("id:save-email");
  await app.waitFor("text:Enter your email");

  await app.type("id:contact-email", "not-an-email");
  await app.press("id:save-email");
  await app.waitFor("text:That is not an email");
  expect(app.shows("text:Saved: not-an-email")).toBe(false);

  await app.clear("id:contact-email");
  await app.type("id:contact-email", "user@example.com");
  await app.press("id:save-email");
  await app.waitFor("text:Saved: user@example.com");
});

test("userinfo renders through the query, with the bearer token sent", async () => {
  const app = await open(PREVIEW, {
    clock: {},
    network: {
      [`GET ${PREVIEW_USERINFO_URL}`]: {
        body: { sub: "user-1", name: "Preview User", email: "preview@example.com" },
      },
    },
  });
  await app.waitFor("text:Preview User");
  expect(app.shows("text:preview@example.com")).toBe(true);
  expect(app.shows("text:Loading profile…")).toBe(false);
  const request = app.requests().find((entry) => entry.url === PREVIEW_USERINFO_URL);
  expect(request?.headers["authorization"]).toBe("Bearer preview-token");
});

test("a failed userinfo shows the error, and the claims readout still renders", async () => {
  const app = await open(PREVIEW, {
    clock: {},
    network: { [`GET ${PREVIEW_USERINFO_URL}`]: { status: 401, body: { error: "invalid_token" } } },
  });
  await app.waitFor("text:Profile failed: Error: userinfo failed: HTTP 401");
  expect(app.shows("text:ID token claims")).toBe(true);
  expect(app.shows(`text:${new Date(1900000000 * 1000).toISOString()}`)).toBe(true);
  expect(app.shows("text:Access token: …d tok")).toBe(true);
  expect(app.shows("text:Refresh token: stored")).toBe(true);
});

test("switching the provider realm reloads the profile, not the cache", async () => {
  const app = await open(PREVIEW, {
    clock: {},
    network: {
      [`GET ${MOCK_BASE_URL}/mock/userinfo`]: { body: { sub: "user-1", name: "Mock User" } },
      [`GET ${MOCK_BASE_URL}/oidc/userinfo`]: { body: { sub: "user-9", name: "OIDC User" } },
    },
  });
  await app.waitFor("id:realm-switch >> text:Mock User");
  await app.press("id:switch-realm");
  await app.waitFor("id:realm-switch >> text:OIDC User");
  // The probe's own card swapped; the stale realm's profile did not linger.
  expect(app.shows("id:realm-switch >> text:Mock User")).toBe(false);
  const loads = app
    .requests()
    .filter((entry) => entry.url === `${MOCK_BASE_URL}/oidc/userinfo`);
  expect(loads).toHaveLength(1);
});

test("claims rows format epoch claims as dates and aud lists joined", () => {
  const rows = claimsToRows({ iss: "x", exp: 1900000000, aud: ["a", "b"], sub: "user-1" });
  expect(rows).toContainEqual({ key: "exp", value: new Date(1900000000 * 1000).toISOString() });
  expect(rows).toContainEqual({ key: "aud", value: "a, b" });
  expect(rows.map((row) => row.key)).toEqual(["iss", "aud", "sub", "exp"]);
  expect(claimsToRows(null)).toEqual([]);
  expect(claimsToRows(PREVIEW_CLAIMS).map((row) => row.key)).toEqual([
    "iss",
    "aud",
    "sub",
    "nonce",
    "exp",
    "iat",
    "name",
    "email",
  ]);
});
