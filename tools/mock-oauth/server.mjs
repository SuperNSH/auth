import http from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createKeyMaterial, jwksDoc, signJwt } from "./jwks.mjs";
import { createStore } from "./store.mjs";
import { providers, tokenErrorBody, APPLE_USER_FIELD, splitScopes } from "./providers.mjs";

// Binds 127.0.0.1 only: this mock must never be reachable off the developer machine.
export async function startMock({ port = 8755 } = {}) {
  const key = createKeyMaterial();
  const store = createStore();
  const control = { deny: false };
  let base = null;

  const server = http.createServer((req, res) => {
    handle(req, res, { key, store, control, base }).catch((err) => {
      sandboxJson(res, 500, { error: "sandbox_error", error_description: String(err?.message ?? err) });
    });
  });

  await new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", resolve);
    server.on("error", reject);
  });
  const addr = server.address();
  base = `http://127.0.0.1:${addr.port}`;

  return {
    server,
    base,
    url: base,
    port: addr.port,
    control,
    store,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      }),
  };
}

async function handle(req, res, ctx) {
  const url = new URL(req.url, "http://127.0.0.1");
  res.setHeader("X-Nsh-Auth-Sandbox", "nsh-auth sandbox (not a real provider)");
  const path = url.pathname;

  // Wildcard CORS is safe on this mock: it binds 127.0.0.1 only, holds no real
  // credentials, and web demos on a different loopback port must exchange
  // tokens and read JWKS from the browser. tools/broker deliberately stays
  // CORS-free.
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type, authorization, accept");
  res.setHeader("access-control-max-age", "600");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  // Issuer (id_token, discovery, MS callback) and picture URLs derive from the
  // request's Host header: clients behind host aliases — the Android emulator's
  // 10.0.2.2, tunnels — must see an issuer that matches their own base URL.
  ctx.base = requestBase(req, ctx.base);

  if (path === "/") return indexPage(res);
  if (path === "/__control") return handleControl(req, res, ctx, url);
  if (path === "/__routes") return sandboxJson(res, 200, routesDoc());
  if (path === "/avatar.png") {
    res.writeHead(200, { "content-type": "image/png", "content-length": AVATAR_PNG.length });
    return res.end(AVATAR_PNG);
  }

  const match = matchProvider(path);
  if (!match) return sandboxJson(res, 404, { error: "not_found", error_description: "nsh-auth sandbox: unknown route. See /__routes." });
  const { prov, tenant } = match;
  res.setHeader("X-Nsh-Auth-Sandbox", prov.realm);
  const ctxTenant = { ...ctx, tenant };

  const r = prov.routes;
  if (path === expand(r.authorize, tenant)) return handleAuthorize(prov, req, res, url, ctxTenant);
  if (path === expand(r.token, tenant)) return handleToken(prov, req, res, url, ctxTenant);
  if (r.userinfo && path === r.userinfo) return handleUserinfo(prov, req, res, url, ctxTenant);
  if (r.revoke && path === r.revoke) return handleRevoke(prov, req, res, url, ctxTenant);
  if (r.debugToken && path === r.debugToken) return handleDebugToken(prov, req, res, url, ctxTenant);
  if (r.jwks && (path === r.jwks || path === r.jwksAlias)) return sandboxJson(res, 200, jwksDoc(ctx.key));
  if (r.discovery && path === expand(r.discovery, tenant)) {
    return sandboxJson(res, 200, prov.discoveryDoc(ctx.base, r, tenant));
  }
  return sandboxJson(res, 404, { error: "not_found", error_description: `nsh-auth sandbox (${prov.realm}): unknown route. See /__routes.` });
}

const expand = (route, tenant) => (route ? route.replace("{tenant}", tenant ?? "common") : null);

// Trusts only authority-shaped Host headers (hostnames, IPv6 brackets, port);
// anything odd falls back to the loopback base the server started on.
function requestBase(req, fallback) {
  const host = req.headers.host;
  if (typeof host === "string" && /^[\w.\-]+(:\d{1,5})?$|^\[[0-9a-fA-F:]+\](:\d{1,5})?$/.test(host)) {
    return `http://${host}`;
  }
  return fallback;
}

function matchProvider(path) {
  for (const prov of Object.values(providers)) {
    if (prov.tenantRoute) {
      if (!path.startsWith("/microsoft/")) continue;
      const segments = path.split("/").filter(Boolean); // ["microsoft", tenant, ...]
      const tenant = segments[1] ?? "";
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(tenant)) return { prov, tenant: null };
      return { prov, tenant };
    }
    if (Object.values(prov.routes).some((route) => route && path === route)) return { prov, tenant: null };
  }
  return null;
}

// --- authorize -----------------------------------------------------------------

function handleAuthorize(prov, req, res, url, ctx) {
  if (req.method !== "GET") return sandboxJson(res, 405, { error: "method_not_allowed", error_description: "authorize is GET only." });
  const q = Object.fromEntries(url.searchParams);
  const redirectUri = q.redirect_uri;
  if (!redirectUri) {
    return sandboxHtml(res, 400, errorPage(prov, "invalid_request", "redirect_uri is required."));
  }

  const responseMode = prov.responseModes.includes(q.response_mode) ? q.response_mode : prov.authorizeMode;
  const respond = (params) => sendCallback(prov, res, redirectUri, responseMode, params);

  const responseTypeOk = q.response_type === "code" || (prov.allowCodeIdToken && q.response_type === "code id_token");
  if (!responseTypeOk) return respond(cbErrorParams("unsupported_response_type", "response_type must be code.", q));
  if (prov.requiresState && !("state" in q)) {
    return respond(cbErrorParams("invalid_request", "state is required.", q));
  }
  if (ctx.control.deny || q.prompt === "deny") {
    return respond(cbErrorParams("access_denied", "The scripted sandbox user denied the request.", q));
  }

  const scopesRaw = q.scope ?? prov.defaultScope;
  const code = ctx.store.putCode({
    provider: prov.id,
    clientId: q.client_id ?? null,
    redirectUri,
    scope: scopesRaw,
    scopes: splitScopes(prov.scopeSeparator, scopesRaw),
    nonce: q.nonce ?? null,
    codeChallenge: q.code_challenge ?? null,
    codeChallengeMethod: q.code_challenge_method ?? null,
    authorizeParams: q,
  });

  const params = { code };
  if ("state" in q) params.state = q.state; // echoed verbatim; the mock never validates state
  if (prov.id === "apple") params.user = APPLE_USER_FIELD;
  if (prov.id === "microsoft") params.iss = `${ctx.base}/microsoft/${ctx.tenant ?? "common"}`;
  respond(params);
}

function cbErrorParams(error, description, q) {
  const params = { error, error_description: description };
  if ("state" in q) params.state = q.state;
  return params;
}

function sendCallback(prov, res, redirectUri, mode, params) {
  if (mode === "form_post") return sandboxHtml(res, 200, formPostPage(prov, redirectUri, params));
  const location = mode === "fragment" ? withFragment(redirectUri, params) : withQuery(redirectUri, params);
  res.writeHead(302, { location });
  res.end();
}

// String-based join: redirect_uri may be a custom scheme (RFC 8252) that URL mangles.
function withQuery(uri, params) {
  const qs = new URLSearchParams(params).toString();
  const hashAt = uri.indexOf("#");
  if (hashAt === -1) {
    if (!uri.includes("?")) return `${uri}?${qs}`;
    return uri.endsWith("?") ? uri + qs : `${uri}&${qs}`;
  }
  const head = uri.slice(0, hashAt);
  const join = head.includes("?") ? (head.endsWith("?") ? "" : "&") : "?";
  const frag = uri.slice(hashAt + 1);
  return frag ? `${head}${join}${qs}#${frag}` : `${head}${join}${qs}`;
}

function withFragment(uri, params) {
  const qs = new URLSearchParams(params).toString();
  const hashAt = uri.indexOf("#");
  if (hashAt === -1) return `${uri}#${qs}`;
  const base = uri.slice(0, hashAt);
  const frag = uri.slice(hashAt + 1);
  return frag ? `${base}#${frag}&${qs}` : `${base}#${qs}`;
}

// --- token ---------------------------------------------------------------------

async function handleToken(prov, req, res, url, ctx) {
  if (!prov.tokenMethods.includes(req.method)) {
    return sandboxJson(res, 405, { error: "method_not_allowed", error_description: `token accepts ${prov.tokenMethods.join(" and ")} only.` });
  }
  let bodyParams = {};
  const raw = await readBody(req);
  if (raw.length > 0) {
    const ct = String(req.headers["content-type"] ?? "");
    if (ct.includes("application/x-www-form-urlencoded")) {
      bodyParams = Object.fromEntries(new URLSearchParams(raw.toString("utf8")));
    } else if (ct.includes("application/json")) {
      if (prov.formOnly) return sendTokenError(prov, req, res, "wrong_content_type");
      try { bodyParams = JSON.parse(raw.toString("utf8")); } catch { return sendTokenError(prov, req, res, "invalid_request"); }
    } else {
      return sendTokenError(prov, req, res, "wrong_content_type");
    }
  }
  const params = { ...Object.fromEntries(url.searchParams), ...bodyParams };

  if (prov.requireClientSecret && !params.client_secret) return sendTokenError(prov, req, res, "invalid_client");

  const grant = params.grant_type ?? "authorization_code";
  if (grant === "authorization_code") return grantAuthorizationCode(prov, req, res, params, ctx);
  if (grant === "refresh_token" && prov.refreshKind === "refresh_token") return grantRefresh(prov, req, res, params, ctx);
  if (grant === "fb_exchange_token" && prov.refreshKind === "fb_exchange_token") return grantFacebookExchange(prov, req, res, params, ctx);
  return sendTokenError(prov, req, res, "unsupported_grant");
}

function grantAuthorizationCode(prov, req, res, params, ctx) {
  const code = params.code;
  if (!code) return sendTokenError(prov, req, res, "invalid_request");
  const entry = ctx.store.getCode(code);
  if (!entry || entry.provider !== prov.id) return sendTokenError(prov, req, res, "unknown_code");
  // Single-use: a replay revokes everything the code already bought (Google-style).
  if (entry.used) {
    if (entry.family) ctx.store.revokeFamily(entry.family.id);
    return sendTokenError(prov, req, res, "code_already_used");
  }
  if (entry.expired) return sendTokenError(prov, req, res, "expired_code");
  if (params.client_id && entry.clientId && params.client_id !== entry.clientId) {
    return sendTokenError(prov, req, res, "client_mismatch");
  }
  if (entry.redirectUri) {
    if (prov.requireRedirectAtToken && !params.redirect_uri) return sendTokenError(prov, req, res, "redirect_mismatch");
    if (params.redirect_uri && params.redirect_uri !== entry.redirectUri) return sendTokenError(prov, req, res, "redirect_mismatch");
  }
  const pkce = checkPkce(entry, params.code_verifier);
  if (!pkce.ok) return sendTokenError(prov, req, res, pkce.reason);

  ctx.store.markCodeUsed(code);
  const family = ctx.store.newFamily({
    provider: prov.id,
    clientId: entry.clientId,
    scopes: entry.scopes,
    scopesRaw: entry.scope,
    nonce: entry.nonce,
  });
  // link the code to its family so a later replay revokes what it already bought
  entry.family = family;
  const wantRefresh = prov.refreshIssuedWhen({
    scopes: entry.scopes,
    scopesRaw: entry.scope,
    authorizeParams: entry.authorizeParams,
    tokenParams: params,
  });
  issueAndRespond(prov, req, res, ctx, { family, wantRefresh });
}

function grantRefresh(prov, req, res, params, ctx) {
  if (prov.refreshNeedsClientId && !params.client_id) return sendTokenError(prov, req, res, "invalid_request");
  const token = params.refresh_token;
  if (!token) return sendTokenError(prov, req, res, "refresh_required");
  const rec = ctx.store.getRefresh(token);
  if (!rec) return sendTokenError(prov, req, res, "unknown_refresh");
  const family = ctx.store.getFamily(rec.family);
  if (rec.revoked || family.revoked) return sendTokenError(prov, req, res, "revoked_refresh");
  if (rec.used) {
    ctx.store.revokeFamily(rec.family);
    return sendTokenError(prov, req, res, "refresh_reused");
  }
  const rotated = ctx.store.rotateRefresh(rec);
  issueAndRespond(prov, req, res, ctx, { family: rotated.family, wantRefresh: true, access: rotated.accessToken, refresh: rotated.refreshToken });
}

function grantFacebookExchange(prov, req, res, params, ctx) {
  const token = params.fb_exchange_token;
  if (!token) return sendTokenError(prov, req, res, "invalid_request");
  const rec = ctx.store.getAccess(token);
  if (!rec || rec.familyRevoked) return sendTokenError(prov, req, res, "fb_token_unknown");
  const family = ctx.store.getFamily(rec.family);
  const access = ctx.store.issueAccessToken(family);
  const body = prov.tokenBody({ access, refresh: null, idToken: null, scopesRaw: family.scopesRaw });
  return sendProviderBody(prov, req, res, 200, body);
}

function issueAndRespond(prov, req, res, ctx, { family, wantRefresh, access, refresh }) {
  access = access ?? ctx.store.issueAccessToken(family);
  refresh = refresh ?? (wantRefresh ? ctx.store.issueRefreshToken(family) : null);
  let idToken = null;
  if (prov.idTokenIssuedWhen({ scopes: family.scopes })) {
    const claims = prov.idTokenClaims({
      base: ctx.base,
      tenant: ctx.tenant,
      clientId: family.clientId ?? "nsh-sandbox-client",
      nonce: family.nonce,
    });
    // nonce flows from the authorize request into the id_token so clients can assert it.
    if (family.nonce) claims.nonce = family.nonce;
    idToken = signJwt(ctx.key, { ...claims, exp: claims.iat + (prov.tokenExpiresIn ?? 3600) });
  }
  const body = prov.tokenBody({ access, refresh, idToken, scopesRaw: family.scopesRaw });
  return sendProviderBody(prov, req, res, 200, body);
}

function checkPkce(entry, verifier) {
  if (!entry.codeChallenge) return { ok: true };
  if (!verifier) return { ok: false, reason: "pkce_missing" };
  if (entry.codeChallengeMethod === "plain") {
    return verifier === entry.codeChallenge ? { ok: true } : { ok: false, reason: "pkce_mismatch" };
  }
  const computed = createHash("sha256").update(verifier).digest("base64url");
  return computed === entry.codeChallenge ? { ok: true } : { ok: false, reason: "pkce_mismatch" };
}

// GitHub negotiates JSON vs form-urlencoded via Accept; everyone else speaks JSON.
function sendProviderBody(prov, req, res, status, body) {
  if (prov.contentNegotiation) {
    const accept = String(req.headers.accept ?? "");
    if (!accept.includes("application/json")) {
      const form = new URLSearchParams(Object.entries(body).filter(([, v]) => v !== undefined)).toString();
      res.writeHead(status, { "content-type": "application/x-www-form-urlencoded; charset=utf-8" });
      return res.end(form);
    }
  }
  sandboxJson(res, status, body);
}

function sendTokenError(prov, req, res, reason) {
  return sendProviderBody(prov, req, res, prov.errorStatus, tokenErrorBody(prov, reason));
}

// --- userinfo / revoke / debug_token ---------------------------------------------

function handleUserinfo(prov, req, res, url, ctx) {
  const token = bearerToken(req) ?? url.searchParams.get("access_token");
  const rec = token ? ctx.store.getAccess(token) : null;
  if (!rec || rec.familyRevoked) return sendUnauthorized(prov, res);
  const family = ctx.store.getFamily(rec.family);
  return sandboxJson(res, 200, prov.userinfoBody({ base: ctx.base, scopes: family.scopes ?? [] }));
}

function bearerToken(req) {
  const header = req.headers.authorization;
  if (!header) return null;
  const [scheme, ...rest] = header.split(" ");
  if (scheme.toLowerCase() === "bearer" || scheme.toLowerCase() === "token") return rest.join(" ") || null;
  return null;
}

function sendUnauthorized(prov, res) {
  const un = prov.unauthorized;
  if (prov.id === "facebook") {
    // Graph refreshes fbtrace_id per response.
    return sandboxJson(res, un.status, {
      error: {
        message: "Invalid OAuth access token.",
        type: "OAuthException",
        code: 190,
        fbtrace_id: `nsh-sandbox-fbtrace-${randomBytes(4).toString("hex")}`,
      },
    });
  }
  const headers = un.headers ?? {};
  const body = un.body === undefined ? {} : un.body;
  sandboxJson(res, un.status, body, headers);
}

function handleRevoke(prov, req, res, url, ctx) {
  if (!prov.revokeMethods.includes(req.method)) {
    return sandboxJson(res, 405, { error: "method_not_allowed", error_description: `revoke accepts ${prov.revokeMethods.join(" and ")} only.` });
  }
  return readBody(req).then((raw) => {
    const bodyParams = raw.length ? Object.fromEntries(new URLSearchParams(raw.toString("utf8"))) : {};
    const params = { ...Object.fromEntries(url.searchParams), ...bodyParams };
    const token = params.token ?? params.access_token;
    if (token) ctx.store.revokeToken(token);
    const { status, body } = prov.revokeSuccess;
    if (body === null) {
      res.writeHead(status, { "content-length": 0 });
      return res.end();
    }
    return sandboxJson(res, status, body);
  });
}

function handleDebugToken(prov, req, res, url, ctx) {
  const params = Object.fromEntries(url.searchParams);
  if (!params.access_token || !params.input_token) {
    return sandboxJson(res, 400, {
      error: { message: "access_token and input_token parameters are required.", type: "OAuthException", code: 100, fbtrace_id: `nsh-sandbox-fbtrace-${randomBytes(4).toString("hex")}` },
    });
  }
  const appTokenOk = Boolean(ctx.store.getAccess(params.access_token));
  const rec = ctx.store.getAccess(params.input_token);
  const valid = appTokenOk && rec && !rec.familyRevoked;
  const data = valid
    ? {
        app_id: "nsh-sandbox-fb-app",
        type: "USER",
        application: prov.realm,
        data_access_expires_at: Math.floor(Date.now() / 1000) + 5183944,
        expires_at: Math.floor(Date.now() / 1000) + 5183944,
        is_valid: true,
        issued_at: Math.floor(Date.now() / 1000) - 60,
        last_refreshed_at: Math.floor(Date.now() / 1000) - 30,
        scopes: ctx.store.getFamily(rec.family).scopes,
        user_id: "nsh-sandbox-fb-user-0001",
      }
    : {
        app_id: "nsh-sandbox-fb-app",
        type: "USER",
        is_valid: false,
        error: {
          code: 190,
          message: appTokenOk ? "The access token is invalid. (sandbox_reason: invalid_token)" : "Invalid app access token. (sandbox_reason: invalid_token)",
          subcode: 467,
        },
      };
  return sandboxJson(res, 200, { data });
}

// --- control & misc ----------------------------------------------------------------

function handleControl(req, res, ctx, url) {
  if (req.method === "GET") {
    return sandboxJson(res, 200, { sandbox: "nsh-auth sandbox", deny: ctx.control.deny, ...ctx.store.stats() });
  }
  if (req.method !== "POST") return sandboxJson(res, 405, { error: "method_not_allowed", error_description: "use GET or POST." });
  return readBody(req).then((raw) => {
    let body = {};
    if (raw.length) {
      try { body = JSON.parse(raw.toString("utf8")); } catch { return sandboxJson(res, 400, { error: "invalid_request", error_description: "control body must be JSON." }); }
    }
    if (typeof body.deny === "boolean") ctx.control.deny = body.deny;
    if (body.reset === true) {
      ctx.store.reset();
      ctx.control.deny = false;
    }
    if (body.expireCodes === true) ctx.store.expireAllCodes();
    return sandboxJson(res, 200, { ok: true, deny: ctx.control.deny, ...ctx.store.stats() });
  });
}

function routesDoc() {
  const out = { sandbox: "nsh-auth sandbox", providers: {} };
  for (const prov of Object.values(providers)) out.providers[prov.id] = prov.routes;
  out.control = { POST: "/__control", fields: { deny: "boolean", reset: "boolean", expireCodes: "boolean" } };
  return out;
}

const AVATAR_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

function indexPage(res) {
  const rows = Object.values(providers)
    .flatMap((p) =>
      Object.entries(p.routes)
        .filter(([, v]) => v)
        .map(([name, v]) => `<tr><td>${p.realm}</td><td><code>${v}</code></td><td>${name}</td></tr>`))
    .join("\n");
  return sandboxHtml(res, 200, `<!doctype html>
<html><head><title>nsh-auth sandbox OAuth mock</title></head>
<body>
<h1>nsh-auth sandbox &mdash; OAuth provider mock</h1>
<p>This is <strong>not</strong> Google, Facebook, Discord, GitHub, Apple, Microsoft or X.
No real credentials exist here; every token is fake and sandbox-prefixed.</p>
<p>Control: <code>POST /__control</code> with JSON <code>{"deny":true}</code>, <code>{"expireCodes":true}</code> or <code>{"reset":true}</code>.
Status: <code>GET /__control</code>. Route table: <code>GET /__routes</code>.</p>
<p>On the Android emulator this host is reachable as <code>http://10.0.2.2:&lt;port&gt;</code>.</p>
<table border="1"><tr><th>provider</th><th>route</th><th>role</th></tr>
${rows}
</table>
</body></html>`);
}

function errorPage(prov, error, description) {
  return `<!doctype html>
<html><head><title>${prov.realm}</title></head>
<body><h1>${prov.realm}</h1>
<p><code>${error}</code>: ${description}</p></body></html>`;
}

function formPostPage(prov, target, params) {
  const inputs = Object.entries(params)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join("\n  ");
  return `<!doctype html>
<html><head><title>${prov.realm}</title></head>
<body>
<p>${prov.realm}: scripted user approved. Submitting the callback form&hellip;</p>
<form method="post" action="${escapeHtml(target)}" id="callback">
  ${inputs}
</form>
<script>document.getElementById('callback').submit();</script>
</body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) { reject(Object.assign(new Error("body too large"), { statusCode: 413 })); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sandboxJson(res, status, body, headers = {}) {
  const payload = body === null ? "" : JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", ...headers });
  res.end(payload);
}

function sandboxHtml(res, status, html) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  res.end(html);
}
