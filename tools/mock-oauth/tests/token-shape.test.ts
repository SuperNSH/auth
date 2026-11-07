import { describe, test, expect } from "bun:test";
import { authorizeOnly, fullFlow, postForm, url, withMock, REDIRECT, CLIENT_ID } from "./helpers.ts";

describe("token response shape per provider", () => {
  test("google: Bearer, 3599, id_token, scope echo; refresh only with access_type=offline", async () => {
    await withMock(async (m) => {
      const noOffline = await fullFlow(m, "google", { access_type: "online" });
      expect(noOffline.token.status).toBe(200);
      expect(noOffline.token.body.token_type).toBe("Bearer");
      expect(noOffline.token.body.expires_in).toBe(3599);
      expect(noOffline.token.body.scope).toContain("openid email profile");
      expect(noOffline.token.body.id_token).toMatch(/^eyJ/);
      expect(noOffline.token.body.refresh_token).toBeUndefined();

      const offline = await fullFlow(m, "google", { access_type: "offline" });
      expect(offline.token.body.refresh_token).toMatch(/^nsh-sandbox-google-rt-/);
    });
  });

  test("facebook: lowercase 'bearer', 60-day expiry, GET query-string exchange, no id_token without openid", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "facebook");
      expect(flow.token.status).toBe(200);
      expect(flow.token.body.token_type).toBe("bearer");
      expect(flow.token.body.expires_in).toBe(5183944);
      expect(flow.token.body.id_token).toBeUndefined();

      // Real Facebook lets the whole token call ride the query string.
      const second = await authorizeOnly(m);
      const viaQuery = await fetch(
        `${m.base}/facebook/v21.0/oauth/access_token?code=${second.code}&code_verifier=${second.verifier}&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT)}`,
        { method: "GET", redirect: "manual" },
      );
      const body = await viaQuery.json();
      expect(viaQuery.status).toBe(200);
      expect(body.access_token).toMatch(/^EAAGnshsandbox/);
    });
  });

  test("facebook: id_token issued when scope includes openid", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "facebook", { scope: "openid,public_profile" });
      expect(flow.token.body.id_token).toMatch(/^eyJ/);
    });
  });

  test("discord: capitalized 'Bearer', 7-day expiry, scope echo, refresh token", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "discord");
      const b = flow.token.body;
      expect(b.token_type).toBe("Bearer");
      expect(b.expires_in).toBe(604800);
      expect(b.scope).toBe("identify email");
      expect(b.refresh_token).toMatch(/^nsh-sandbox-discord-rt-/);
      expect(b.id_token).toBeUndefined(); // Discord has no OIDC id_token
    });
  });

  test("github: form-encoded by default, JSON with Accept, bearer, no refresh without offline_access", async () => {
    await withMock(async (m) => {
      // default Accept: form-urlencoded body (the real GitHub default)
      const { code, verifier } = await authorizeOnly(m, "github");
      const formRes = await postForm(url(m, "github", "token"), { code, code_verifier: verifier });
      expect(formRes.status).toBe(200);
      expect(formRes.text).not.toMatch(/^\{/);
      const form = new URLSearchParams(formRes.text);
      expect(form.get("access_token")).toMatch(/^gho_nshsandbox/);
      expect(form.get("token_type")).toBe("bearer");
      expect(form.get("scope")).toBe("read:user");
      expect(form.get("refresh_token")).toBeNull();

      // Accept: application/json → JSON body
      const jsonFlow = await fullFlow(m, "github");
      expect(jsonFlow.token.body.access_token).toMatch(/^gho_nshsandbox/);
      expect(jsonFlow.token.body.token_type).toBe("bearer");
      expect(jsonFlow.token.body.refresh_token).toBeUndefined();
    });
  });

  test("github: offline_access yields refresh_token, expires_in 28800, refresh_token_expires_in", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "github", { scope: "read:user offline_access" });
      const b = flow.token.body;
      expect(b.refresh_token).toMatch(/^ghr_nshsandbox/);
      expect(b.expires_in).toBe(28800);
      expect(b.refresh_token_expires_in).toBe(15897600);
    });
  });

  test("apple: no scope field, id_token + refresh_token, 3600s", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "apple");
      const b = flow.token.body;
      expect(flow.token.status).toBe(200);
      expect(b.token_type).toBe("Bearer");
      expect(b.expires_in).toBe(3600);
      expect(b.refresh_token).toMatch(/^nsh-sandbox-apple-rt-/);
      expect(b.id_token).toMatch(/^eyJ/);
      expect(b.scope).toBeUndefined(); // Apple omits scope from the token response
    });
  });

  test("microsoft: ext_expires_in, scope echo, refresh with offline_access, id_token with openid", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "microsoft");
      const b = flow.token.body;
      expect(b.token_type).toBe("Bearer");
      expect(b.expires_in).toBe(3599);
      expect(b.ext_expires_in).toBe(3599);
      expect(b.scope).toContain("offline_access");
      expect(b.refresh_token).toMatch(/^nsh-sandbox-msrt-/);
      expect(b.id_token).toMatch(/^eyJ/);

      const noOffline = await fullFlow(m, "microsoft", { scope: "openid profile email" });
      expect(noOffline.token.body.refresh_token).toBeUndefined(); // no offline_access, no refresh token
    });
  });

  test("x: lowercase 'bearer', 7200s, scope echo, refresh with offline.access", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "x");
      const b = flow.token.body;
      expect(b.token_type).toBe("bearer");
      expect(b.expires_in).toBe(7200);
      expect(b.scope).toBe("tweet.read users.read offline.access");
      expect(b.refresh_token).toMatch(/^nsh-sandbox-x-rt-/);
      expect(b.id_token).toBeUndefined();

      const noOffline = await fullFlow(m, "x", { scope: "users.read" });
      expect(noOffline.token.body.refresh_token).toBeUndefined();
    });
  });

  test("oidc: RFC-shape response with id_token and refresh", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "oidc");
      const b = flow.token.body;
      expect(b.access_token).toMatch(/^nsh-sandbox-oidc-at-/);
      expect(b.token_type).toBe("Bearer");
      expect(b.expires_in).toBe(3600);
      expect(b.refresh_token).toBeTruthy();
      expect(b.scope).toBe("openid email profile offline_access");
      expect(b.id_token).toMatch(/^eyJ/);
    });
  });

  test("mock: plain provider always issues an id_token", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "mock");
      const b = flow.token.body;
      expect(b.access_token).toMatch(/^nsh-sandbox-mock-at-/);
      expect(b.refresh_token).toBeTruthy();
      expect(b.id_token).toMatch(/^eyJ/);
    });
  });

  test("POST on authorize is rejected 405", async () => {
    await withMock(async (m) => {
      const res = await postForm(url(m, "google", "authorize"), {});
      expect(res.status).toBe(405);
    });
  });
});
