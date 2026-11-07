import { describe, test, expect, afterAll } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes } from "node:crypto";
import { startMock } from "../../mock-oauth/server.mjs";

const mainPath = fileURLToPath(new URL("../main.mjs", import.meta.url));
const REDIRECT = "http://127.0.0.1:9/callback";
const CLIENT_ID = "nsh-auth-sandbox-github-cid";
const SECRET = "nsh-sandbox-broker-secret";

// one shared mock for the whole suite; broker children are spawned per case
const mock = await startMock({ port: 0 });
const tokenUrl = `${mock.base}/github/login/oauth/access_token`;
const children: ChildProcess[] = [];
afterAll(async () => {
  for (const child of children) child.kill("SIGTERM");
  await mock.close();
});

function spawnBroker(env: Record<string, string | undefined> = {}) {
  const child = spawn(process.execPath, [mainPath, "--port", "0"], {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(child);
  return child;
}

function readUrlLine(child: ChildProcess): Promise<{ stdout: string; url: string }> {
  return new Promise((resolve, reject) => {
    let out = "";
    child.stdout!.on("data", (d) => {
      out += d;
      const match = out.match(/BROKER_URL=(http:\/\/127\.0\.0\.1:\d+)/);
      if (match) resolve({ stdout: out, url: match[1] });
    });
    child.on("exit", (code) => reject(new Error(`broker exited early code=${code}: ${out}${child.stderr?.read()?.toString() ?? ""}`)));
    setTimeout(() => reject(new Error(`no BROKER_URL line; stdout: ${out}`)), 5000);
  });
}

// full GitHub web-flow leg against the mock, returning the fresh code + verifier
async function githubAuthorize() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const qs = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    scope: "read:user offline_access",
    state: "nsh-sandbox-state-broker",
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const res = await fetch(`${mock.base}/github/login/oauth/authorize?${qs}`, { redirect: "manual" });
  expect(res.status).toBe(302);
  const callback = new URL(res.headers.get("location")!);
  expect(callback.searchParams.get("state")).toBe("nsh-sandbox-state-broker");
  return { code: callback.searchParams.get("code")!, verifier };
}

function waitFor<T>(fn: () => T | null | undefined, timeoutMs: number): Promise<T | null> {
  return new Promise((resolve) => {
    const started = Date.now();
    const tick = () => {
      const value = fn();
      if (value) return resolve(value);
      if (Date.now() - started > timeoutMs) return resolve(null);
      setTimeout(tick, 25);
    };
    tick();
  });
}

describe("GitHub-via-broker end-to-end against the mock", () => {
  test("authorize at mock -> broker /token -> usable access token", async () => {
    const child = spawnBroker({ GITHUB_CLIENT_SECRET: SECRET, BROKER_TOKEN_URL: tokenUrl, BROKER_CLIENT_ID: CLIENT_ID });
    const { stdout: bootLine, url } = await readUrlLine(child);
    let stdout = bootLine;
    child.stdout!.on("data", (d) => (stdout += d));

    const { code, verifier } = await githubAuthorize();
    const res = await fetch(`${url}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code, code_verifier: verifier, redirect_uri: REDIRECT }),
    });
    expect(res.status).toBe(200);
    const token = await res.json();
    // GitHub JSON shape through the broker (Accept: application/json was set upstream)
    expect(token.access_token).toMatch(/^gho_nshsandbox/);
    expect(token.token_type).toBe("bearer");
    expect(token.scope).toBe("read:user offline_access");
    expect(token.refresh_token).toMatch(/^ghr_nshsandbox/);

    // the token the broker returned actually works at the provider
    const user = await fetch(`${mock.base}/github/api/user`, {
      headers: { authorization: `Bearer ${token.access_token}` },
    });
    expect(user.status).toBe(200);
    expect((await user.json()).login).toBe("nsh-sandbox-user");

    // wait for the request log line, then assert it leaks nothing
    const logLine = await waitFor(() => stdout.match(/POST \/token -> 200 .+ms/), 3000);
    expect(logLine).toBeTruthy();

    // the client secret and tokens never appear in broker logs
    expect(stdout).not.toContain(SECRET);
    expect(stdout).not.toContain("gho_");
    expect(stdout).not.toContain("ghr_");
    expect(stdout).not.toContain(code);
  });

  test("provider errors pass through untouched (GitHub 200 + in-band error)", async () => {
    const child = spawnBroker({ GITHUB_CLIENT_SECRET: SECRET, BROKER_TOKEN_URL: tokenUrl, BROKER_CLIENT_ID: CLIENT_ID });
    const { url } = await readUrlLine(child);
    const res = await fetch(`${url}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: "nsh-sandbox-code-never-issued" }),
    });
    expect(res.status).toBe(200); // GitHub quirk preserved verbatim
    const body = await res.json();
    expect(body.error).toBe("bad_verification_code");
    expect(body.error_description).toContain("unknown_code");
  });
});

describe("broker endpoint and input validation", () => {
  test("only POST /token exists", async () => {
    const child = spawnBroker({ GITHUB_CLIENT_SECRET: SECRET, BROKER_TOKEN_URL: tokenUrl });
    const { url } = await readUrlLine(child);
    for (const [method, path] of [["GET", "/"], ["GET", "/token"], ["POST", "/other"], ["DELETE", "/token"]] as const) {
      const res = await fetch(`${url}${path}`, { method });
      expect(res.status).toBe(404);
    }
  });

  test("missing code is rejected locally without contacting the provider", async () => {
    const child = spawnBroker({ GITHUB_CLIENT_SECRET: SECRET, BROKER_TOKEN_URL: tokenUrl });
    const { url } = await readUrlLine(child);
    const res = await fetch(`${url}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code_verifier: "v", redirect_uri: REDIRECT }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_request");
  });

  test("non-JSON body is 400", async () => {
    const child = spawnBroker({ GITHUB_CLIENT_SECRET: SECRET, BROKER_TOKEN_URL: tokenUrl });
    const { url } = await readUrlLine(child);
    const res = await fetch(`${url}/token`, { method: "POST", body: "code=x" });
    expect(res.status).toBe(400);
  });
});

describe("secret handling", () => {
  test("refuses to start without GITHUB_CLIENT_SECRET", async () => {
    const child = spawnBroker({ GITHUB_CLIENT_SECRET: undefined, BROKER_TOKEN_URL: tokenUrl });
    const [code, stderr] = await new Promise<[number | null, string]>((resolve) => {
      let err = "";
      child.stderr!.on("data", (d) => (err += d));
      child.on("exit", (code) => resolve([code, err]));
    });
    expect(code).not.toBe(0);
    expect(stderr).toContain("GITHUB_CLIENT_SECRET");
    expect(stderr).not.toContain(SECRET);
  });

  test("README documents run command, env vars and the no-secret guarantee", async () => {
    const readme = await Bun.file(new URL("../README.md", import.meta.url)).text();
    expect(readme).toContain("GITHUB_CLIENT_SECRET");
    expect(readme).toContain("BROKER_TOKEN_URL");
    expect(readme).toContain("POST /token");
    expect(readme).toContain("--port 0");
  });
});
