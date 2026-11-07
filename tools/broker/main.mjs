#!/usr/bin/env node
import { startBroker } from "./server.mjs";

function portFromArgs(argv) {
  const flagIndex = argv.indexOf("--port");
  if (flagIndex !== -1 && argv[flagIndex + 1] !== undefined) return Number(argv[flagIndex + 1]);
  const eq = argv.find((a) => a.startsWith("--port="));
  if (eq) return Number(eq.slice("--port=".length));
  return 8756;
}

const port = portFromArgs(process.argv);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`invalid --port: ${process.argv.join(" ")}`);
  process.exit(1);
}

const secret = process.env.GITHUB_CLIENT_SECRET;
if (!secret) {
  console.error("broker: GITHUB_CLIENT_SECRET is not set. The broker holds the provider's client");
  console.error("secret for confidential flows (GitHub needs it at the token endpoint) and refuses");
  console.error("to start without it. Never inline it in code or ship it in an app bundle.");
  process.exit(1);
}

const tokenUrl = process.env.BROKER_TOKEN_URL ?? "http://127.0.0.1:8755/github/login/oauth/access_token";
const clientId = process.env.BROKER_CLIENT_ID ?? "nsh-auth-sandbox-client-id";

const broker = await startBroker({ port, tokenUrl, clientId, clientSecret: secret });
console.log(`BROKER_URL=${broker.url}`);
console.log(`broker forwarding to ${tokenUrl} (client secret loaded from GITHUB_CLIENT_SECRET)`);

const shutdown = () => { broker.close().then(() => process.exit(0)); };
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
