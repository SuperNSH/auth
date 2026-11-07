import { expect } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { startMock } from "../server.mjs";
import { providers } from "../providers.mjs";

export type Mock = Awaited<ReturnType<typeof startMock>>;

export const REDIRECT = "http://127.0.0.1:9/callback";
export const CLIENT_ID = "nsh-auth-sandbox-client";

// One server per test; close() destroys keep-alive sockets so bun test exits cleanly.
export async function withMock(fn: (m: Mock) => Promise<void> | void) {
  const m = await startMock({ port: 0 });
  try {
    await fn(m);
  } finally {
    await m.close();
  }
}

export function route(prov: string, role: string): string {
  const r = (providers as any)[prov].routes[role];
  if (!r) throw new Error(`${prov} has no ${role} route`);
  return r.replace("{tenant}", "common");
}

export function url(m: Mock, prov: string, role: string, params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return `${m.base}${route(prov, role)}${qs ? "?" + qs : ""}`;
}

export async function get(rawUrl: string, headers: Record<string, string> = {}) {
  const res = await fetch(rawUrl, { headers, redirect: "manual" });
  const text = await res.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch {}
  return { status: res.status, text, body, headers: res.headers, location: res.headers.get("location") };
}

export async function postForm(rawUrl: string, params: Record<string, string>, headers: Record<string, string> = {}) {
  const res = await fetch(rawUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(params),
  });
  const text = await res.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch {}
  return { status: res.status, text, body, headers: res.headers };
}

export async function control(m: Mock, body: Record<string, unknown>) {
  const res = await fetch(`${m.base}/__control`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

export function pkce(method: "S256" | "plain" = "S256") {
  const verifier = randomBytes(32).toString("base64url");
  const challenge =
    method === "plain" ? verifier : createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge, method };
}

export interface Callback {
  status: number;
  mode: string;
  params: Record<string, string>;
  location: string | null;
  html: string | null;
}

// Follows the authorize response into callback params for every response mode.
export async function authorize(m: Mock, prov: string, params: Record<string, string>): Promise<Callback> {
  const res = await get(url(m, prov, "authorize", params));
  if (res.status === 302 && res.location) {
    const hashAt = res.location.indexOf("#");
    const [before, fragment] = hashAt === -1 ? [res.location, null] : [res.location.slice(0, hashAt), res.location.slice(hashAt + 1)];
    if (fragment !== null) {
      return { status: res.status, mode: "fragment", params: Object.fromEntries(new URLSearchParams(fragment)), location: res.location, html: null };
    }
    return { status: res.status, mode: "query", params: Object.fromEntries(new URL(before).searchParams), location: res.location, html: null };
  }
  if (typeof res.body === "string" && res.body.includes("<form")) {
    const inputs: Record<string, string> = {};
    for (const match of res.body.matchAll(/<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"/g)) {
      inputs[match[1]] = decodeHtmlAttr(match[2]);
    }
    return { status: res.status, mode: "form_post", params: inputs, location: null, html: res.body };
  }
  return { status: res.status, mode: "other", params: {}, location: res.location, html: typeof res.body === "string" ? res.body : null };
}

function decodeHtmlAttr(value: string) {
  return value.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

export interface Flow {
  code: string;
  callback: Callback;
  token: { status: number; body: any; text: string };
  verifier?: string;
}

// Happy-path authorize + token exchange with PKCE, honoring Apple's client_secret and form_post.
export async function fullFlow(
  m: Mock,
  prov: string,
  authorizeParams: Record<string, string> = {},
  tokenParams: Record<string, string> = {},
): Promise<Flow> {
  const method = (authorizeParams.code_challenge_method as "S256" | "plain") ?? "S256";
  const { verifier, challenge } = pkce(method);
  const callback = await authorize(m, prov, {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    scope: (providers as any)[prov].defaultScope,
    state: "nsh-sandbox-state-123",
    code_challenge: challenge,
    code_challenge_method: method,
    ...authorizeParams,
  });
  // Apple delivers form_post (200 + HTML form); everyone else 302-redirects.
  expect(callback.params.code).toBeTruthy();
  const extra: Record<string, string> = { client_id: CLIENT_ID, redirect_uri: REDIRECT, code_verifier: verifier ?? "" };
  if (prov === "apple") extra.client_secret = "nsh-sandbox-apple-secret";
  const token = await postForm(url(m, prov, "token"), {
    code: callback.params.code,
    ...extra,
    ...tokenParams,
  }, { accept: "application/json" }); // GitHub needs this to answer JSON; everyone else ignores it
  return { code: callback.params.code, callback, token, verifier };
}

// Authorize-only happy path with PKCE bound; returns the code and verifier for custom exchange styles.
export async function authorizeOnly(m: Mock, prov = "facebook", opts: { scope?: string; pkce?: boolean } = {}) {
  const method = "S256" as const;
  const { verifier, challenge } = pkce();
  const params: Record<string, string> = {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    scope: opts.scope ?? (providers as any)[prov].defaultScope,
    state: "nsh-sandbox-state-123",
  };
  if (opts.pkce !== false) {
    params.code_challenge = challenge;
    params.code_challenge_method = method;
  }
  const callback = await authorize(m, prov, params);
  expect(callback.params.code).toBeTruthy();
  return { code: callback.params.code, verifier, callback };
}

// Decodes a JWT payload without verifying (verification tests live in jwt.test.ts).
export function decodeJwt(jwt: string): { header: any; claims: any } {
  const [h, p] = jwt.split(".");
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString()),
    claims: JSON.parse(Buffer.from(p, "base64url").toString()),
  };
}
