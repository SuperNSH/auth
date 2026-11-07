import { describe, test, expect } from "bun:test";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { startMock } from "../server.mjs";
import { get, withMock } from "./helpers.ts";

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
