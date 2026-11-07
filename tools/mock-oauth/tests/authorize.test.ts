import { describe, test, expect } from "bun:test";
import { authorize, control, REDIRECT, withMock, url } from "./helpers.ts";

const ALL = ["google", "facebook", "discord", "github", "apple", "microsoft", "x", "oidc", "mock"];

describe("authorize happy path (each provider's real shape)", () => {
  for (const prov of ALL) {
    test(`${prov}: approve redirects with code and echoes state verbatim`, async () => {
      await withMock(async (m) => {
        const cb = await authorize(m, prov, {
          response_type: "code",
          client_id: "nsh-auth-sandbox-client",
          redirect_uri: REDIRECT,
          scope: "email",
          state: "st&te=weird +ünïcode", // hostile state must come back byte-identical
        });
        expect(cb.params.error).toBeUndefined();
        expect(cb.params.code).toMatch(/^nsh-sandbox-code-/);
        expect(cb.params.state).toBe("st&te=weird +ünïcode");
        expect(cb.params.error_description).toBeUndefined();
      });
    });
  }

  test("apple: form_post callback carries code, state and the scripted user profile", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "apple", {
        response_type: "code",
        client_id: "nsh.sandbox.apple",
        redirect_uri: REDIRECT,
        scope: "name email",
        state: "apple-state",
        response_mode: "form_post",
      });
      expect(cb.mode).toBe("form_post");
      expect(cb.html).toContain("nsh-auth sandbox (not Apple)");
      expect(cb.params.user).toContain("sandbox.user@nsh-auth.invalid");
      expect(JSON.parse(cb.params.user).name.firstName).toBe("Sandbox");
    });
  });

  test("microsoft: fragment response_mode and iss in the callback", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "microsoft", {
        response_type: "code",
        redirect_uri: REDIRECT,
        state: "ms",
        response_mode: "fragment",
      });
      expect(cb.mode).toBe("fragment");
      expect(cb.params.code).toBeTruthy();
      expect(cb.params.iss).toBe(`${m.base}/microsoft/common`);
    });
  });

  test("microsoft: form_post response_mode returns an auto-submitting form", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "microsoft", {
        response_type: "code",
        redirect_uri: REDIRECT,
        state: "ms",
        response_mode: "form_post",
      });
      expect(cb.mode).toBe("form_post");
      expect(cb.params.code).toBeTruthy();
      expect(cb.params.state).toBe("ms");
    });
  });
});

describe("scripted user denial", () => {
  for (const prov of ["google", "github", "discord", "x", "microsoft"]) {
    test(`${prov}: prompt=deny redirects with error=access_denied and echoes state`, async () => {
      await withMock(async (m) => {
        const cb = await authorize(m, prov, {
          response_type: "code",
          redirect_uri: REDIRECT,
          state: "s-deny",
          prompt: "deny",
        });
        expect(cb.params.error).toBe("access_denied");
        expect(cb.params.state).toBe("s-deny");
        expect(cb.params.code).toBeUndefined();
      });
    });
  }

  test("apple: denial arrives in the form_post body", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "apple", {
        response_type: "code",
        redirect_uri: REDIRECT,
        state: "apple-deny",
        prompt: "deny",
      });
      expect(cb.params.error).toBe("access_denied");
      expect(cb.params.state).toBe("apple-deny");
    });
  });

  test("/__control deny=true denies every provider until reset", async () => {
    await withMock(async (m) => {
      await control(m, { deny: true });
      for (const prov of ["google", "github", "oidc"]) {
        const cb = await authorize(m, prov, { response_type: "code", redirect_uri: REDIRECT, state: "ctl" });
        expect(cb.params.error).toBe("access_denied");
      }
      await control(m, { reset: true });
      const cb = await authorize(m, "google", { response_type: "code", redirect_uri: REDIRECT, state: "ctl" });
      expect(cb.params.code).toBeTruthy();
    });
  });
});

describe("authorize request validation (provider-real failures)", () => {
  test("google: missing redirect_uri is a branded 400 page, never a redirect", async () => {
    await withMock(async (m) => {
      const res = await get2(url(m, "google", "authorize", { response_type: "code" }));
      expect(res.status).toBe(400);
      expect(res.text).toContain("nsh-auth sandbox (not Google)");
    });
  });

  test("google: missing response_type redirects unsupported_response_type with state echoed", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "google", { redirect_uri: REDIRECT, state: "rt" });
      expect(cb.params.error).toBe("unsupported_response_type");
      expect(cb.params.state).toBe("rt");
    });
  });

  test("x: missing state is invalid_request (real X requires state)", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "x", { response_type: "code", redirect_uri: REDIRECT });
      expect(cb.params.error).toBe("invalid_request");
    });
  });

  test("apple: missing state is invalid_request (web flow)", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "apple", { response_type: "code", redirect_uri: REDIRECT });
      expect(cb.params.error).toBe("invalid_request");
    });
  });

  test("apple: response_type 'code id_token' is accepted", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "apple", { response_type: "code id_token", redirect_uri: REDIRECT, state: "a" });
      expect(cb.params.code).toBeTruthy();
    });
  });

  test("custom-scheme redirect (RFC 8252) keeps code and state", async () => {
    await withMock(async (m) => {
      const cb = await authorize(m, "google", {
        response_type: "code",
        redirect_uri: "nsh-auth-sandbox://callback",
        state: "app",
      });
      expect(cb.mode).toBe("query");
      expect(cb.params.code).toBeTruthy();
      expect(cb.params.state).toBe("app");
    });
  });
});

// local fetch that never follows redirects and keeps raw text
async function get2(rawUrl: string) {
  const res = await fetch(rawUrl, { redirect: "manual" });
  return { status: res.status, text: await res.text() };
}
