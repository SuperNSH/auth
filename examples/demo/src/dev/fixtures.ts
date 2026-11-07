// Fake data and the demo's fixed OAuth constants, for the UI preview and the
// tests. Pure values: importing this file has no nsh side effects, unlike the
// preview entry, which mounts. src/auth.ts and App.test.tsx share these.
// MOCK_BASE_URL must equal the package's DEFAULT_MOCK_BASE_URL.
export const MOCK_BASE_URL = "http://127.0.0.1:8755";
export const CLIENT_ID = "nsh-auth-sandbox-client";
/** The scheme both hosts register (native/ios, host-android): scheme nsh.auth.sandbox, path callback. */
export const REDIRECT_URI = "nsh.auth.sandbox://callback";
/** Storage key for the base that actually served a sign-in (survives bare relaunches). */
export const MOCK_BASE_URL_STORAGE_KEY = "nsh-auth:mockBaseUrl";
/** The mock provider's default scopes in src/providers.ts; tests assert the URL carries them. */
export const SCOPES = ["openid", "profile", "email", "offline_access"];

export const PREVIEW_USERINFO_URL = `${MOCK_BASE_URL}/mock/userinfo`;

export const PREVIEW_CLAIMS: Record<string, unknown> = {
  iss: MOCK_BASE_URL,
  aud: CLIENT_ID,
  sub: "user-1",
  nonce: "preview-nonce",
  exp: 1900000000,
  iat: 1760000000,
  name: "Preview User",
  email: "preview@example.com",
};
