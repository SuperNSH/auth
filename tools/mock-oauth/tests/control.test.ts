import { describe, test, expect } from "bun:test";
import { authorize, authorizeOnly, control, get, postForm, REDIRECT, url, withMock } from "./helpers.ts";

describe("/__control", () => {
  test("GET reports sandbox status and live counters", async () => {
    await withMock(async (m) => {
      const res = await get(`${m.base}/__control`);
      expect(res.status).toBe(200);
      expect(res.body.sandbox).toBe("nsh-auth sandbox");
      expect(res.body.deny).toBe(false);
      expect(typeof res.body.codes).toBe("number");
    });
  });

  test("POST deny=true flips global scripting; every provider denies until reset", async () => {
    await withMock(async (m) => {
      const set = await control(m, { deny: true });
      expect(set.body.deny).toBe(true);
      const cb = await authorize(m, "google", { response_type: "code", redirect_uri: REDIRECT, state: "s" });
      expect(cb.params.error).toBe("access_denied");
      expect(await control(m, {}).then((r) => r.body.deny)).toBe(true);
      await control(m, { deny: false });
      const cb2 = await authorize(m, "google", { response_type: "code", redirect_uri: REDIRECT, state: "s" });
      expect(cb2.params.code).toBeTruthy();
    });
  });

  test("POST expireCodes makes outstanding codes return expired_code", async () => {
    await withMock(async (m) => {
      const { code } = await authorizeOnly(m, "google");
      await control(m, { expireCodes: true });
      const t = await postForm(url(m, "google", "token"), { code, redirect_uri: REDIRECT });
      expect(t.body.error_description).toContain("expired_code");
    });
  });

  test("POST reset clears codes, tokens and the deny flag", async () => {
    await withMock(async (m) => {
      const { code } = await authorizeOnly(m, "mock");
      await control(m, { deny: true });
      const reset = await control(m, { reset: true });
      expect(reset.body.codes).toBe(0);
      expect(reset.body.deny).toBe(false);
      const t = await postForm(url(m, "mock", "token"), { code });
      expect(t.status).toBe(400);
      expect(t.body.error_description).toContain("unknown_code");
    });
  });

  test("non-JSON control body is 400", async () => {
    await withMock(async (m) => {
      const res = await fetch(`${m.base}/__control`, { method: "POST", body: "not json" });
      expect(res.status).toBe(400);
    });
  });
});
