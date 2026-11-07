import { describe, test, expect } from "bun:test";
import { authorize, authorizeOnly, control, fullFlow, postForm, REDIRECT, url, withMock } from "./helpers.ts";

describe("expired codes (120s TTL, forced via /__control)", () => {
  test("google: invalid_grant expired_code", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "google");
      await control(m, { expireCodes: true });
      const t = await postForm(url(m, "google", "token"), { code: cb.code, redirect_uri: REDIRECT });
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("invalid_grant");
      expect(t.body.error_description).toContain("expired_code");
    });
  });

  test("github: in-band error with HTTP 200 quirk", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "github");
      await control(m, { expireCodes: true });
      const t = await postForm(url(m, "github", "token"), { code: cb.code }, { accept: "application/json" });
      expect(t.status).toBe(200); // real GitHub reports token errors with 200
      expect(t.body.error).toBe("bad_verification_code");
      expect(t.body.error_description).toContain("expired_code");
    });
  });

  test("microsoft: invalid_grant with AADSTS70008 in error_codes", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "microsoft");
      await control(m, { expireCodes: true });
      const t = await postForm(url(m, "microsoft", "token"), { code: cb.code, redirect_uri: REDIRECT });
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("invalid_grant");
      expect(t.body.error_codes).toContain(70008);
      expect(t.body.error_description).toContain("AADSTS70008");
      expect(t.body.error_description).toMatch(/expired/i);
      expect(t.body.correlation_id).toBe("nsh-sandbox-correlation");
    });
  });

  test("facebook: OAuthException mentioning the expired code", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "facebook");
      await control(m, { expireCodes: true });
      const t = await postForm(url(m, "facebook", "token"), { code: cb.code, redirect_uri: REDIRECT });
      expect(t.status).toBe(400);
      expect(t.body.error.code).toBe(400);
      expect(t.body.error.type).toBe("OAuthException");
      expect(t.body.error.message).toMatch(/expired/i);
      expect(t.body.error.fbtrace_id).toMatch(/^nsh-sandbox-fbtrace-/);
    });
  });

  // Consumers classify expired codes from invalid_grant + /expired/i description;
  // the wire error code must never be a bare "expired_code".
  for (const prov of ["discord", "x", "oidc", "mock"]) {
    test(`${prov}: invalid_grant with expired-saying description`, async () => {
      await withMock(async (m) => {
        const cb = await authorizeOnly(m, prov);
        await control(m, { expireCodes: true });
        const t = await postForm(url(m, prov, "token"), { code: cb.code, redirect_uri: REDIRECT });
        expect(t.status).toBe(400);
        expect(t.body.error).toBe("invalid_grant");
        expect(t.body.error_description).toMatch(/expired/i);
        expect(t.body.error_description).toContain("sandbox_reason: expired_code");
        expect(JSON.stringify(t.body)).not.toContain('"error":"expired_code"');
      });
    });
  }

  test("apple: invalid_grant expired_code", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "apple");
      await control(m, { expireCodes: true });
      const t = await postForm(url(m, "apple", "token"), {
        code: cb.code, client_id: "nsh.sandbox.apple", client_secret: "sc", redirect_uri: REDIRECT,
      });
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("invalid_grant");
      expect(t.body.error_description).toContain("expired_code"); // not some other invalid_grant
    });
  });
});

describe("unknown and single-use codes", () => {
  test("google: unknown code is invalid_grant", async () => {
    await withMock(async (m) => {
      const t = await postForm(url(m, "google", "token"), { code: "nsh-sandbox-code-nope", redirect_uri: REDIRECT });
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("invalid_grant");
      expect(t.body.error_description).toContain("unknown_code");
    });
  });

  test("discord: unknown code shape", async () => {
    await withMock(async (m) => {
      const t = await postForm(url(m, "discord", "token"), { code: "nope" });
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("invalid_grant");
    });
  });

  test("google: code exchanges exactly once; replay fails with code_already_used", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google", { access_type: "offline" });
      expect(flow.token.status).toBe(200);
      const replay = await postForm(url(m, "google", "token"), {
        code: flow.code, redirect_uri: REDIRECT, code_verifier: flow.verifier!,
      });
      expect(replay.status).toBe(400);
      expect(replay.body.error_description).toContain("code_already_used");
    });
  });

  test("google: replaying a code revokes the whole token family (Google-style)", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "google", { access_type: "offline" });
      const refresh1 = await postForm(url(m, "google", "token"), {
        grant_type: "refresh_token", refresh_token: flow.token.body.refresh_token,
      });
      expect(refresh1.status).toBe(200);
      await postForm(url(m, "google", "token"), { code: flow.code, redirect_uri: REDIRECT, code_verifier: flow.verifier! });
      // the rotated refresh token from before the replay is now dead too
      const refresh2 = await postForm(url(m, "google", "token"), {
        grant_type: "refresh_token", refresh_token: refresh1.body.refresh_token,
      });
      expect(refresh2.status).toBe(400);
      expect(refresh2.body.error_description).toContain("revoked");
    });
  });
});

describe("PKCE enforcement", () => {
  test("google: wrong S256 verifier is pkce_mismatch", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "google");
      const t = await postForm(url(m, "google", "token"), {
        code: cb.code, redirect_uri: REDIRECT, code_verifier: "wrong-verifier-wrong-verifier-wrong",
      });
      expect(t.status).toBe(400);
      expect(t.body.error_description).toContain("pkce_mismatch");
    });
  });

  test("google: missing verifier with challenge present is pkce_missing", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "google");
      const t = await postForm(url(m, "google", "token"), { code: cb.code, redirect_uri: REDIRECT });
      expect(t.status).toBe(400);
      expect(t.body.error_description).toContain("pkce_missing");
    });
  });

  test("x: plain method accepted when the verifier equals the challenge", async () => {
    await withMock(async (m) => {
      const flow = await fullFlow(m, "x", { code_challenge_method: "plain" });
      expect(flow.token.status).toBe(200);
      expect(flow.token.body.access_token).toBeTruthy();
    });
  });

  test("github: S256 PKCE verified on exchange", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "github");
      const bad = await postForm(url(m, "github", "token"), { code: cb.code, code_verifier: "not-it" }, { accept: "application/json" });
      expect(bad.status).toBe(200);
      expect(bad.body.error_description).toContain("pkce_mismatch");
    });
  });
});

describe("binding and parameter mismatch errors", () => {
  test("google: mismatched client_id is client_mismatch", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "google");
      const t = await postForm(url(m, "google", "token"), {
        code: cb.code, client_id: "nsh-auth-someone-else.apps.googleusercontent.com", redirect_uri: REDIRECT,
      });
      expect(t.status).toBe(400);
      expect(t.body.error_description).toContain("client_mismatch");
    });
  });

  test("google: mismatched redirect_uri is redirect_mismatch", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "google");
      const t = await postForm(url(m, "google", "token"), { code: cb.code, redirect_uri: "http://127.0.0.1:9/other" });
      expect(t.status).toBe(400);
      expect(t.body.error_description).toContain("redirect_mismatch");
    });
  });

  test("google: missing redirect_uri (required at token) is redirect_mismatch", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "google");
      const t = await postForm(url(m, "google", "token"), { code: cb.code });
      expect(t.status).toBe(400);
      expect(t.body.error_description).toContain("redirect_mismatch");
    });
  });

  test("discord: JSON token body rejected with wrong_content_type", async () => {
    await withMock(async (m) => {
      const res = await fetch(url(m, "discord", "token"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: "x" }),
      });
      const b = await res.json();
      expect(res.status).toBe(400);
      expect(b.error).toBe("invalid_request");
      expect(b.error_description).toContain("x-www-form-urlencoded");
    });
  });

  test("apple: missing client_secret is invalid_client", async () => {
    await withMock(async (m) => {
      const cb = await authorizeOnly(m, "apple");
      const t = await postForm(url(m, "apple", "token"), {
        code: cb.code, client_id: "nsh.sandbox.apple", redirect_uri: REDIRECT,
      });
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("invalid_client");
    });
  });

  test("google: unsupported grant_type is unsupported_grant_type", async () => {
    await withMock(async (m) => {
      const t = await postForm(url(m, "google", "token"), { grant_type: "password", username: "x", password: "y" });
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("unsupported_grant_type");
    });
  });

  test("google: missing code is invalid_request", async () => {
    await withMock(async (m) => {
      const t = await postForm(url(m, "google", "token"), {});
      expect(t.status).toBe(400);
      expect(t.body.error).toBe("invalid_request");
    });
  });
});
