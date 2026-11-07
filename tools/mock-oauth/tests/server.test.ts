import { describe, test, expect } from "bun:test";
import { spawn } from "node:child_process";
import { get as nodeGet, request } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { startMock } from "../server.mjs";
import { decodeJwt, get, postForm, url, withMock, REDIRECT, CLIENT_ID } from "./helpers.ts";

// Raw request so the Host header can name an alias (10.0.2.2) while the
// connection still targets loopback — exactly the emulator rewrite shape.
function rawGet(m: any, path: string, hostHeader: string): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: m.port, path, headers: { host: hostHeader } },
      (res) => {
        let text = "";
        res.on("data", (d) => (text += d));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("issuer is derived from the request Host header", () => {
  test("Host: 10.0.2.2:8755 mints id_token iss and discovery issuer on the alias", async () => {
    await withMock(async (m) => {
      const host = "10.0.2.2:8755";
      // discovery reflects the alias host
      const disc = await rawGet(m, "/mock/.well-known/openid-configuration", host);
      expect(disc.status).toBe(200);
      expect(JSON.parse(disc.text).issuer).toBe("http://10.0.2.2:8755/mock");

      // authorize + exchange over the alias host mints an alias-scheme issuer
      const cb = await authorizeViaRaw(m, "/mock/authorize", host);
      expect(cb.code).toBeTruthy();
      const tok = await postForm(url(m, "mock", "token"), {
        code: cb.code, client_id: CLIENT_ID, redirect_uri: REDIRECT,
      }, { accept: "application/json", host });
      expect(tok.status).toBe(200);
      const { claims } = decodeJwt(tok.body.id_token);
      expect(claims.iss).toBe("http://10.0.2.2:8755/mock");

      // 127.0.0.1 requests keep seeing the loopback issuer on the same server
      const localDisc = await get(url(m, "mock", "discovery"));
      expect(JSON.parse(localDisc.text).issuer).toBe(`${m.base}/mock`);
    });
  });

  test("google behaves the same under the alias host", async () => {
    await withMock(async (m) => {
      const disc = await rawGet(m, "/google/.well-known/openid-configuration", "10.0.2.2:8755");
      expect(JSON.parse(disc.text).issuer).toBe("http://10.0.2.2:8755/google");
      const cb = await authorizeViaRaw(m, "/google/o/oauth2/v2/auth", "10.0.2.2:8755");
      const tok = await postForm(url(m, "google", "token"), {
        code: cb.code, client_id: CLIENT_ID, redirect_uri: REDIRECT,
      }, { accept: "application/json", host: "10.0.2.2:8755" });
      expect(tok.status).toBe(200);
      expect(decodeJwt(tok.body.id_token).claims.iss).toBe("http://10.0.2.2:8755/google");
    });
  });

  test("a request without a Host header (HTTP/1.0 style) falls back to the loopback base", async () => {
    await withMock(async (m) => {
      const disc = await new Promise<{ status: number; text: string }>((resolve, reject) => {
        nodeGet({ host: "127.0.0.1", port: m.port, path: "/mock/.well-known/openid-configuration" }, (res) => {
          let text = "";
          res.on("data", (d) => (text += d));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
        }).on("error", reject);
      });
      expect(disc.status).toBe(200);
      expect(JSON.parse(disc.text).issuer).toBe(`${m.base}/mock`);
    });
  });
});

// authorize over a raw connection with an explicit Host header
async function authorizeViaRaw(m: any, path: string, hostHeader: string): Promise<{ code: string }> {
  const qs = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    state: "host-alias",
  });
  const res = await new Promise<{ status: number; location: string | null }>((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: m.port, path: `${path}?${qs}`, headers: { host: hostHeader } },
      (res) => resolve({ status: res.statusCode ?? 0, location: res.headers.location ?? null }),
    );
    req.on("error", reject);
    req.end();
  });
  expect(res.status).toBe(302);
  const code = new URL(res.location!).searchParams.get("code") ?? "";
  return { code };
}

describe("server binding and CLI", () => {
  test("binds 127.0.0.1 only", async () => {
    const m = await startMock({ port: 0 });
    try {
      expect(m.server.address().address).toBe("127.0.0.1");
      expect(m.port).toBeGreaterThan(0);
    } finally {
      await m.close();
    }
  });

  test("index page is unmistakably sandbox-branded", async () => {
    await withMock(async (m) => {
      const res = await get(`${m.base}/`);
      expect(res.status).toBe(200);
      expect(res.text).toContain("nsh-auth sandbox");
      expect(res.text).toContain("10.0.2.2");
      expect(res.text).toContain("/github/login/oauth/authorize");
    });
  });

  test("every response carries the sandbox header", async () => {
    await withMock(async (m) => {
      const res = await fetch(`${m.base}/google/token`, { method: "POST" });
      expect(res.headers.get("x-nsh-auth-sandbox")).toContain("nsh-auth sandbox");
    });
  });

  test("unknown route is a 404 JSON pointing at /__routes", async () => {
    await withMock(async (m) => {
      const res = await get(`${m.base}/acme/authorize`);
      expect(res.status).toBe(404);
      expect(res.body.error).toBe("not_found");
    });
  });

  test("avatar.png serves a PNG", async () => {
    await withMock(async (m) => {
      const res = await fetch(`${m.base}/avatar.png`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("image/png");
      const bytes = new Uint8Array(await res.arrayBuffer());
      expect(bytes[0]).toBe(0x89); // PNG magic
    });
  });

  test("__routes documents every provider namespace", async () => {
    await withMock(async (m) => {
      const res = await get(`${m.base}/__routes`);
      expect(Object.keys(res.body.providers).sort()).toEqual(
        ["apple", "discord", "facebook", "github", "google", "microsoft", "mock", "oidc", "x"],
      );
    });
  });

  test("CLI: --port 0 prints MOCK_URL on stdout and serves the index", async () => {
    const mainPath = fileURLToPath(new URL("../main.mjs", import.meta.url));
    const child = spawn(process.execPath, [mainPath, "--port", "0"], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      const stdout = await new Promise<string>((resolve, reject) => {
        let out = "";
        child.stdout!.on("data", (d) => {
          out += d;
          const match = out.match(/MOCK_URL=(http:\/\/127\.0\.0\.1:\d+)/);
          if (match) resolve(out);
        });
        child.on("exit", (code) => reject(new Error(`exited early code=${code}: ${out}`)));
        setTimeout(() => reject(new Error(`no MOCK_URL line; stdout: ${out}`)), 5000);
      });
      const mockUrl = stdout.match(/MOCK_URL=(http:\/\/127\.0\.0\.1:\d+)/)![1];
      const res = await fetch(mockUrl + "/");
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("nsh-auth sandbox");
      expect(stdout).toContain(`http://10.0.2.2:`);
    } finally {
      child.kill("SIGTERM");
    }
  });

  test("CLI: invalid --port exits non-zero", async () => {
    const mainPath = fileURLToPath(new URL("../main.mjs", import.meta.url));
    const child = spawn(process.execPath, [mainPath, "--port", "notaport"], { stdio: ["ignore", "pipe", "pipe"] });
    const code = await new Promise<number>((resolve) => child.on("exit", resolve));
    expect(code).not.toBe(0);
  });

  test("README documents the run command and route table", async () => {
    const readme = await readFile(fileURLToPath(new URL("../README.md", import.meta.url)), "utf8");
    expect(readme).toContain("--port 0");
    expect(readme).toContain("10.0.2.2");
    expect(readme).toContain("/google/token");
    expect(readme).toContain("/__control");
  });
});
