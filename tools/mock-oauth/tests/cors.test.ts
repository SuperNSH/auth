import { describe, test, expect } from "bun:test";
import { get, postForm, url, withMock } from "./helpers.ts";

// Web demos run on a different loopback port than the mock; every response must
// be CORS-open or the browser blocks the token exchange and JWKS fetch.
describe("CORS: loopback web clients can complete the loop", () => {
  test("OPTIONS preflight to a token route is 204 with wildcard ACAO", async () => {
    await withMock(async (m) => {
      const res = await fetch(url(m, "mock", "token"), { method: "OPTIONS" });
      expect(res.status).toBe(204);
      expect(res.headers.get("access-control-allow-origin")).toBe("*");
      expect(res.headers.get("access-control-allow-methods")).toContain("POST");
      expect(res.headers.get("access-control-allow-headers")).toContain("content-type");
      expect(res.headers.get("x-nsh-auth-sandbox")).toContain("nsh-auth sandbox");
    });
  });

  test("POST token response carries ACAO so the browser hands the body to the page", async () => {
    await withMock(async (m) => {
      const res = await fetch(url(m, "mock", "token"), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ code: "nsh-sandbox-code-nope" }),
      });
      expect(res.status).toBe(400);
      expect(res.headers.get("access-control-allow-origin")).toBe("*");
    });
  });

  test("GET jwks and discovery carry ACAO", async () => {
    await withMock(async (m) => {
      for (const raw of [url(m, "mock", "jwks"), url(m, "mock", "discovery"), url(m, "google", "jwks")]) {
        const res = await fetch(raw);
        expect(res.headers.get("access-control-allow-origin")).toBe("*");
      }
    });
  });

  test("preflight to an unknown route is still 204 (browsers preflight before 404 exists)", async () => {
    await withMock(async (m) => {
      const res = await fetch(`${m.base}/acme/token`, { method: "OPTIONS" });
      expect(res.status).toBe(204);
      expect(res.headers.get("access-control-allow-origin")).toBe("*");
    });
  });

  test("postForm helper (json-capable requests) keeps the CORS header on errors", async () => {
    await withMock(async (m) => {
      const res = await postForm(url(m, "google", "token"), {});
      expect(res.status).toBe(400);
      expect(res.headers.get("access-control-allow-origin")).toBe("*");
    });
  });
});
