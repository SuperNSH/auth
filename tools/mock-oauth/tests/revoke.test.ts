import { describe, test, expect } from "bun:test";
import { fullFlow, get, postForm, url, withMock } from "./helpers.ts";

describe("revoke endpoints kill the token family", () => {
  test("google: POST /google/revoke?token=… → 200 empty; access token then 401 at userinfo", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google", { access_type: "offline" });
      const revoke = await fetch(`${m.base}/google/revoke?token=${encodeURIComponent(flow.token.body.access_token)}`, { method: "POST" });
      expect(revoke.status).toBe(200);
      expect(await revoke.text()).toBe("");
      const ui = await get(`${m.base}/google/userinfo`, { authorization: `Bearer ${flow.token.body.access_token}` });
      expect(ui.status).toBe(401);
      const r = await postForm(url(m, "google", "token"), {
        grant_type: "refresh_token", refresh_token: flow.token.body.refresh_token,
      });
      expect(r.status).toBe(400);
    });
  });

  test("discord: POST /discord/oauth2/token/revoke → 204; @me then 401", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "discord");
      const revoke = await fetch(url(m, "discord", "revoke"), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: flow.token.body.access_token }),
      });
      expect(revoke.status).toBe(204);
      const me = await get(`${m.base}/discord/api/users/@me`, { authorization: `Bearer ${flow.token.body.access_token}` });
      expect(me.status).toBe(401);
      expect(me.body.message).toBe("401: Unauthorized");
    });
  });

  test("apple: POST /apple/auth/revoke → 200; refresh then fails", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "apple");
      const revoke = await fetch(url(m, "apple", "revoke"), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: flow.token.body.refresh_token, client_id: "nsh-auth-sandbox-client" }),
      });
      expect(revoke.status).toBe(200);
      const r = await postForm(url(m, "apple", "token"), {
        grant_type: "refresh_token",
        refresh_token: flow.token.body.refresh_token,
        client_id: "nsh-auth-sandbox-client",
        client_secret: "nsh-sandbox-apple-secret",
      });
      expect(r.status).toBe(400);
      expect(r.body.error).toBe("invalid_grant");
    });
  });

  test("github: DELETE /github/revoke → 204; API then 401 Bad credentials", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "github");
      const revoke = await fetch(`${url(m, "github", "revoke")}?token=${encodeURIComponent(flow.token.body.access_token)}`, { method: "DELETE" });
      expect(revoke.status).toBe(204);
      const api = await get(`${m.base}/github/api/user`, { authorization: `token ${flow.token.body.access_token}` });
      expect(api.status).toBe(401);
      expect(api.body.message).toBe("Bad credentials");
    });
  });

  test("facebook: DELETE /facebook/permissions → {success:true}; /me then code 190", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "facebook");
      const revoke = await fetch(`${url(m, "facebook", "revoke")}?access_token=${encodeURIComponent(flow.token.body.access_token)}`, { method: "DELETE" });
      expect(revoke.status).toBe(200);
      expect((await revoke.json()).success).toBe(true);
      const me = await get(`${m.base}/facebook/me?access_token=${encodeURIComponent(flow.token.body.access_token)}`);
      expect(me.status).toBe(400);
      expect(me.body.error.code).toBe(190);
    });
  });

  test("x: POST /x/2/oauth2/revoke → 200 {}; refresh then fails", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "x");
      const revoke = await fetch(url(m, "x", "revoke"), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: flow.token.body.refresh_token, client_id: "nsh-auth-sandbox-client" }),
      });
      expect(revoke.status).toBe(200);
      expect(await revoke.json()).toEqual({});
      const r = await postForm(url(m, "x", "token"), {
        grant_type: "refresh_token", refresh_token: flow.token.body.refresh_token, client_id: "nsh-auth-sandbox-client",
      });
      expect(r.status).toBe(400);
      expect(r.body.error_description).toContain("revoked");
    });
  });

  test("revoking an unknown token still succeeds (RFC 7009)", async () => {
    await withMock(async (m) => {
      const revoke = await fetch(`${m.base}/google/revoke?token=nsh-sandbox-never-issued`, { method: "POST" });
      expect(revoke.status).toBe(200);
    });
  });
});
