import { describe, test, expect } from "bun:test";
import { fullFlow, get, url, withMock } from "./helpers.ts";

async function flowFor(m: any, prov: string) {
  const flow = await fullFlow(m, prov);
  expect(flow.token.status).toBe(200);
  return flow.token.body;
}

describe("userinfo / me endpoints in each provider's shape", () => {
  test("google: GET /google/userinfo with Bearer", async () => {
    await withMock(async (m) => {
      const tok = await flowFor(m, "google");
      const ui = await get(`${m.base}/google/userinfo`, { authorization: `Bearer ${tok.access_token}` });
      expect(ui.status).toBe(200);
      expect(ui.body.sub).toBe("nsh-sandbox-google-user-0001");
      expect(ui.body.email).toBe("sandbox.user@nsh-auth.invalid");
      expect(ui.body.email_verified).toBe(true);
      expect(ui.body.picture).toBe(`${m.base}/avatar.png`);
    });
  });

  test("facebook: GET /facebook/me with query-string access_token", async () => {
    await withMock(async (m) => {
      const tok = await flowFor(m, "facebook");
      const me = await get(`${m.base}/facebook/me?access_token=${encodeURIComponent(tok.access_token)}`);
      expect(me.status).toBe(200);
      expect(me.body.id).toBe("nsh-sandbox-fb-user-0001");
      expect(me.body.email).toBe("sandbox.user@nsh-auth.invalid"); // email scope granted
      expect(me.body.picture.data.is_silhouette).toBe(false);
    });
  });

  test("facebook: /me omits email when email scope was not granted", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "facebook", { scope: "public_profile" });
      const me = await get(`${m.base}/facebook/me?access_token=${encodeURIComponent(flow.token.body.access_token)}`);
      expect(me.status).toBe(200);
      expect(me.body.email).toBeUndefined();
    });
  });

  test("discord: GET /discord/api/users/@me with Bearer", async () => {
    await withMock(async (m) => {
      const tok = await flowFor(m, "discord");
      const me = await get(`${m.base}/discord/api/users/@me`, { authorization: `Bearer ${tok.access_token}` });
      expect(me.status).toBe(200);
      expect(me.body.username).toBe("nsh_sandbox_user");
      expect(me.body.global_name).toBe("Sandbox User");
      expect(me.body.email).toBe("sandbox.user@nsh-auth.invalid");
    });
  });

  test("github: GET /github/api/user accepts Bearer and 'token' prefix", async () => {
    await withMock(async (m) => {
      const tok = await flowFor(m, "github");
      for (const header of [`Bearer ${tok.access_token}`, `token ${tok.access_token}`]) {
        const api = await get(`${m.base}/github/api/user`, { authorization: header });
        expect(api.status).toBe(200);
        expect(api.body.login).toBe("nsh-sandbox-user");
        expect(api.body.id).toBe(1000000001);
        expect(api.body.type).toBe("User");
        expect(api.body.email).toBe("sandbox.user@nsh-auth.invalid");
      }
    });
  });

  test("microsoft: GET graph-style userinfo", async () => {
    await withMock(async (m) => {
      const tok = await flowFor(m, "microsoft");
      const ui = await get(`${m.base}/microsoft/common/oidc/userinfo`, { authorization: `Bearer ${tok.access_token}` });
      expect(ui.status).toBe(200);
      expect(ui.body.sub).toBe("00000000-0000-4000-8000-000000000001");
      expect(ui.body.name).toBe("Sandbox User");
    });
  });

  test("x: GET /x/2/users/me wraps the user in data", async () => {
    await withMock(async (m) => {
      const tok = await flowFor(m, "x");
      const me = await get(`${m.base}/x/2/users/me`, { authorization: `Bearer ${tok.access_token}` });
      expect(me.status).toBe(200);
      expect(me.body.data.id).toBe("1900000000000000001");
      expect(me.body.data.username).toBe("nsh_sandbox_user");
    });
  });

  test("oidc and mock: standard userinfo with sub", async () => {
    await withMock(async (m) => {
      for (const prov of ["oidc", "mock"]) {
        const tok = await flowFor(m, prov);
        const ui = await get(url(m, prov, "userinfo"), { authorization: `Bearer ${tok.access_token}` });
        expect(ui.status).toBe(200);
        expect(ui.body.sub).toMatch(/^nsh-sandbox-/);
        expect(ui.body.picture).toBe(`${m.base}/avatar.png`);
      }
    });
  });

  test("apple has no userinfo endpoint (404) — profile arrives in the authorize callback", async () => {
    await withMock(async (m) => {
      const res = await get(`${m.base}/apple/userinfo`);
      expect(res.status).toBe(404);
    });
  });
});

describe("invalid tokens rejected in each provider's error shape", () => {
  test("google: 401 invalid_token", async () => {
    await withMock(async (m) => {
      const ui = await get(`${m.base}/google/userinfo`, { authorization: "Bearer nsh-sandbox-google-at-bogus" });
      expect(ui.status).toBe(401);
      expect(ui.body.error).toBe("invalid_token");
    });
  });

  test("facebook: 400 code 190", async () => {
    await withMock(async (m) => {
      const me = await get(`${m.base}/facebook/me?access_token=EAAGbogus`);
      expect(me.status).toBe(400);
      expect(me.body.error.code).toBe(190);
      expect(me.body.error.type).toBe("OAuthException");
    });
  });

  test("discord: 401 message shape", async () => {
    await withMock(async (m) => {
      const me = await get(`${m.base}/discord/api/users/@me`, { authorization: "Bearer bogus" });
      expect(me.status).toBe(401);
      expect(me.body.message).toBe("401: Unauthorized");
      expect(me.body.code).toBe(0);
    });
  });

  test("github: 401 Bad credentials", async () => {
    await withMock(async (m) => {
      const api = await get(`${m.base}/github/api/user`, { authorization: "Bearer bogus" });
      expect(api.status).toBe(401);
      expect(api.body.message).toBe("Bad credentials");
    });
  });

  test("microsoft: 401 with WWW-Authenticate and empty body", async () => {
    await withMock(async (m) => {
      const ui = await get(`${m.base}/microsoft/common/oidc/userinfo`, { authorization: "Bearer bogus" });
      expect(ui.status).toBe(401);
      expect(ui.text).toBe("");
      expect(ui.headers.get("www-authenticate")).toContain("invalid_token");
    });
  });

  test("x: 401 problem-details shape", async () => {
    await withMock(async (m) => {
      const me = await get(`${m.base}/x/2/users/me`, { authorization: "Bearer bogus" });
      expect(me.status).toBe(401);
      expect(me.body.title).toBe("Unauthorized");
      expect(me.body.status).toBe(401);
    });
  });
});
