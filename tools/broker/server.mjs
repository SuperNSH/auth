import http from "node:http";

// Reference token broker for confidential clients (e.g. GitHub's web flow, which
// still needs client_secret at the token endpoint). Exposes exactly one route:
// POST /token {code, code_verifier, redirect_uri} -> provider token response.
//
// The client secret lives only in the environment; it is never written to disk
// or logs, and request/response bodies are never logged either.

export function startBroker({ port = 0, tokenUrl, clientId, clientSecret, log = (msg) => console.log(msg) } = {}) {
  if (!clientSecret) {
    throw new Error(
      "broker: client secret is empty — set the GITHUB_CLIENT_SECRET env var; refusing to start without it.",
    );
  }
  if (!tokenUrl) {
    throw new Error("broker: tokenUrl is required (BROKER_TOKEN_URL).");
  }

  const server = http.createServer((req, res) => {
    handle(req, res, { tokenUrl, clientId, clientSecret, log }).catch((err) => {
      if (err?.code === "PROVIDER_UNREACHABLE") {
        return sendJson(res, 502, { error: "provider_unavailable", error_description: "could not reach the token endpoint." });
      }
      sendJson(res, 500, { error: "broker_error", error_description: "internal error." });
    });
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    // loopback only: the broker serves the app owner's own machine
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      resolve({
        server,
        port: addr.port,
        url: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((done) => {
            server.close(() => done());
            if (typeof server.closeAllConnections === "function") server.closeAllConnections();
          }),
      });
    });
  });
}

async function handle(req, res, { tokenUrl, clientId, clientSecret, log }) {
  const path = new URL(req.url, "http://127.0.0.1").pathname;
  if (req.method !== "POST" || path !== "/token") {
    return sendJson(res, 404, { error: "not_found", error_description: "the broker exposes POST /token only." });
  }

  const raw = await readBody(req);
  if (raw.length > 1024 * 1024) return sendJson(res, 413, { error: "invalid_request", error_description: "body too large." });
  let body;
  try {
    body = JSON.parse(raw.toString("utf8") || "{}");
  } catch {
    return sendJson(res, 400, { error: "invalid_request", error_description: "body must be JSON." });
  }
  const { code, code_verifier: codeVerifier, redirect_uri: redirectUri } = body ?? {};
  if (typeof code !== "string" || code.length === 0) {
    return sendJson(res, 400, { error: "invalid_request", error_description: "code is required." });
  }

  const form = new URLSearchParams({
    client_id: String(clientId ?? ""),
    client_secret: clientSecret,
    code,
  });
  if (typeof redirectUri === "string" && redirectUri) form.set("redirect_uri", redirectUri);
  if (typeof codeVerifier === "string" && codeVerifier) form.set("code_verifier", codeVerifier);

  const started = Date.now();
  let upstream;
  try {
    upstream = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        // GitHub answers form-encoded unless this header asks for JSON
        accept: "application/json",
      },
      body: form,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    const err = new Error("provider unreachable");
    err.code = "PROVIDER_UNREACHABLE";
    throw err;
  }

  const text = await upstream.text();
  // log carries no token, code or verifier — only method, outcome and latency
  log(`POST /token -> ${upstream.status} ${Date.now() - started}ms`);

  res.writeHead(upstream.status, { "content-type": "application/json; charset=utf-8" });
  res.end(text);
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

function sendJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}
