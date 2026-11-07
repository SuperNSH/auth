#!/usr/bin/env node
import { startMock } from "./server.mjs";

function portFromArgs(argv) {
  const flagIndex = argv.indexOf("--port");
  if (flagIndex !== -1 && argv[flagIndex + 1] !== undefined) return Number(argv[flagIndex + 1]);
  const eq = argv.find((a) => a.startsWith("--port="));
  if (eq) return Number(eq.slice("--port=".length));
  return 8755;
}

const port = portFromArgs(process.argv);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`invalid --port: ${process.argv.join(" ")}`);
  process.exit(1);
}

const mock = await startMock({ port });
console.log("nsh-auth sandbox OAuth mock — not Google, Facebook, Discord, GitHub, Apple, Microsoft or X");
console.log(`MOCK_URL=${mock.url}`);
console.log(`Android emulator: reach this server as http://10.0.2.2:${mock.port}`);
console.log('control: POST /__control {"deny":true|false} | {"expireCodes":true} | {"reset":true}');

const shutdown = () => { mock.close().then(() => process.exit(0)); };
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
