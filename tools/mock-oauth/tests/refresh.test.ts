import { describe, test, expect } from "bun:test";
import { fullFlow, get, postForm, url, withMock, REDIRECT } from "./helpers.ts";

describe("refresh token rotation (single-use)", () => {
  test("google: refresh rotates tokens; the old refresh token dies and kills the family", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google", { access_type: "offline" });
      const first = await postForm(url(m, "google", "token"), {
        grant_type: "refresh_token",
        refresh_token: flow.token.body.refresh_token,
      });
      expect(first.status).toBe(200);
      expect(first.body.refresh_token).toMatch(/^nsh-sandbox-google-rt-/);
      expect(first.body.refresh_token).not.toBe(flow.token.body.refresh_token);
      expect(first.body.access_token).not.toBe(flow.token.body.access_token);

      // reuse of the spent refresh token: revoked, and the rotated one is dead too
      const reuse = await postForm(url(m, "google", "token"), {
        grant_type: "refresh_token",
        refresh_token: flow.token.body.refresh_token,
      });
      expect(reuse.status).toBe(400);
      expect(reuse.body.error_description).toContain("refresh_reused");

      const latest = await postForm(url(m, "google", "token"), {
        grant_type: "refresh_token",
        refresh_token: first.body.refresh_token,
      });
      expect(latest.status).toBe(400);
      expect(latest.body.error_description).toContain("revoked");
    });
  });

  test("discord: refresh keeps the 7-day expiry and rotates", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "discord");
      const r = await postForm(url(m, "discord", "token"), {
        grant_type: "refresh_token", refresh_token: flow.token.body.refresh_token,
      });
      expect(r.status).toBe(200);
      expect(r.body.expires_in).toBe(604800);
      expect(r.body.token_type).toBe("Bearer");
      expect(r.body.refresh_token).not.toBe(flow.token.body.refresh_token);
    });
  });

  test("x: refresh requires client_id (public client), then rotates", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "x");
      const missing = await postForm(url(m, "x", "token"), {
        grant_type: "refresh_token", refresh_token: flow.token.body.refresh_token,
      });
      expect(missing.status).toBe(400);
      expect(missing.body.error).toBe("invalid_request");

      const ok = await postForm(url(m, "x", "token"), {
        grant_type: "refresh_token",
        refresh_token: flow.token.body.refresh_token,
        client_id: "nsh-auth-sandbox-client",
      });
      expect(ok.status).toBe(200);
      expect(ok.body.token_type).toBe("bearer");
      expect(ok.body.expires_in).toBe(7200);
      expect(ok.body.refresh_token).not.toBe(flow.token.body.refresh_token);
    });
  });

  test("github: offline_access refresh flows through /login/oauth/access_token", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "github", { scope: "read:user offline_access" });
      const r = await postForm(url(m, "github", "token"), {
        grant_type: "refresh_token",
        refresh_token: flow.token.body.refresh_token,
      }, { accept: "application/json" });
      expect(r.status).toBe(200);
      expect(r.body.access_token).toMatch(/^gho_nshsandbox/);
      expect(r.body.refresh_token).toMatch(/^ghr_nshsandbox/);
      expect(r.body.refresh_token).not.toBe(flow.token.body.refresh_token);
    });
  });

  test("apple: refresh rotates (client_secret required, as with real Apple)", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "apple");
      const r = await postForm(url(m, "apple", "token"), {
        grant_type: "refresh_token",
        refresh_token: flow.token.body.refresh_token,
        client_id: "nsh-auth-sandbox-client",
        client_secret: "nsh-sandbox-apple-secret",
      });
      expect(r.status).toBe(200);
      expect(r.body.id_token).toMatch(/^eyJ/);
      expect(r.body.refresh_token).not.toBe(flow.token.body.refresh_token);
    });
  });

  test("oidc and mock: refresh rotates", async () => {
    await withMock(async (m) => {
      for (const prov of ["oidc", "mock"]) {
        const flow = await fullFlow(m, prov);
        const r = await postForm(url(m, prov, "token"), {
          grant_type: "refresh_token", refresh_token: flow.token.body.refresh_token,
        });
        expect(r.status).toBe(200);
        expect(r.body.refresh_token).not.toBe(flow.token.body.refresh_token);
      }
    });
  });
});

describe("revoked refresh", () => {
  test("google: after provider revoke, refresh is invalid_grant", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google", { access_type: "offline" });
      const revoke = await fetch(`${m.base}/google/revoke?token=${encodeURIComponent(flow.token.body.refresh_token)}`, { method: "POST" });
      expect(revoke.status).toBe(200);
      const r = await postForm(url(m, "google", "token"), {
        grant_type: "refresh_token", refresh_token: flow.token.body.refresh_token,
      });
      expect(r.status).toBe(400);
      expect(r.body.error_description).toContain("revoked");
    });
  });
});

describe("facebook long-lived exchange (grant_type=fb_exchange_token)", () => {
  test("issues a fresh long-lived access token that works at /me", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "facebook");
      const ex = await postForm(url(m, "facebook", "token"), {
        grant_type: "fb_exchange_token",
        fb_exchange_token: flow.token.body.access_token,
      });
      expect(ex.status).toBe(200);
      expect(ex.body.token_type).toBe("bearer");
      expect(ex.body.expires_in).toBe(5183944);
      expect(ex.body.access_token).not.toBe(flow.token.body.access_token);

      const me = await get(`${m.base}/facebook/me?access_token=${encodeURIComponent(ex.body.access_token)}`);
      expect(me.status).toBe(200);
      expect(me.body.id).toBe("nsh-sandbox-fb-user-0001");
    });
  });

  test("unknown fb_exchange_token is code 190", async () => {
    await withMock(async (m) => {
      const ex = await postForm(url(m, "facebook", "token"), {
        grant_type: "fb_exchange_token", fb_exchange_token: "EAAGnope",
      });
      expect(ex.status).toBe(400);
      expect(ex.body.error.code).toBe(190);
    });
  });
});
