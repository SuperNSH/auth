#!/usr/bin/env node
// Smoke gate: greps the app source trees and build outputs for secret-shaped
// strings and exits non-zero on any hit. Fake, sandbox-marked values are fine;
// anything that looks real is a gate failure.
//
// Usage: node tools/check-no-secrets.mjs [--root <dir>]...
//   --root may repeat; defaults to the repository root (parent of tools/).
// Scanned per root: packages/, crates/, native/, fixtures/ and examples/ in
// full — examples/ covers both source trees and build outputs.

import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = join(scriptDir, "..");

// Values carrying any of these are sandbox fakes, not secrets.
const FAKE_MARKER = /sandbox|example|dummy|fake|placeholder|sample|nsh-auth|localhost|127\.0\.0\.1|\.invalid|not-?real|acme|test/i;

// examples/ must stay in this list: a secret pasted into example source is as
// fatal as one in packages/ (audit finding, 2026-11).
const SCAN_DIRS = ["packages", "crates", "native", "fixtures", "examples"];
const SKIP_DIRS = new Set(["node_modules", ".git", "target", ".zflow", ".zcode", ".agents", ".breakrun"]);
const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".otf",
  ".mp4", ".mp3", ".mov", ".zip", ".gz", ".tar", ".jar", ".apk", ".ipa", ".dylib", ".so",
  ".dll", ".bin", ".pdf", ".a", ".o", ".aab", ".xcframework", ".node",
]);
const MAX_FILE_BYTES = 5 * 1024 * 1024;

// [name, regex, fakeCheckValueGroup?] — group 1 (or fakeGroup) is checked against FAKE_MARKER.
const VALUE_PATTERNS = [
  ["client_secret-literal", /client_secret["']?\s*[:=]\s*["']([A-Za-z0-9_./+=-]{10,})["']/i, 1],
  ["client_secret-inline", /\bclient_secret=([A-Za-z0-9_-]{20,})(?=[\s&"']|$)/, 1],
  ["google-client-id", /\b(\d{8,20}-[a-z0-9]{15,}\.apps\.googleusercontent\.com)\b/i, 1],
  ["numeric-client-id", /\b(?:client_id|app_id)["']?\s*[:=]\s*["']?(\d{16,20})\b/, 1],
  ["github-token", /\bgh[pousr]_[A-Za-z0-9]{30,50}\b/, 0],
  ["github-pat", /\bgithub_pat_[A-Za-z0-9_]{30,}\b/, 0],
  ["github-app-id", /\b(?:Iv1\.[0-9a-fA-F]{16}|Ov23li[A-Za-z0-9]{14,})\b/, 0],
  ["google-oauth-secret-prefix", /\bGOCSPX-[A-Za-z0-9_-]{15,}\b/, 0],
  ["google-api-key", /\bAIza[A-Za-z0-9_-]{30,}\b/, 0],
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/, 0],
  ["slack-token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, 0],
  ["openai-key", /\bsk-(?:ant|proj)-[A-Za-z0-9_-]{20,}\b/, 0],
  ["gitlab-pat", /\bglpat-[A-Za-z0-9_-]{18,}\b/, 0],
  ["square-token", /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{20,}\b/, 0],
  ["facebook-token", /\bEA[A-Z]{4}[A-Za-z0-9]{30,}\b/, 0],
];

const PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const GOOGLE_SERVICE_FILES = new Set(["google-services.json", "googleservice-info.plist"]);

function collectArgs(argv) {
  const roots = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--root") {
      const value = argv[++i];
      if (!value) return { error: "--root needs a directory" };
      roots.push(value);
    } else if (argv[i]?.startsWith("--root=")) {
      roots.push(argv[i].slice("--root=".length));
    } else {
      return { error: `unknown argument: ${argv[i]}` };
    }
  }
  return { roots: roots.length ? roots : [DEFAULT_ROOT] };
}

function listFiles(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // missing tree — nothing to scan
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      listFiles(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
}

function isProbablyBinary(path, buffer) {
  const ext = path.slice(path.lastIndexOf(".")).toLowerCase();
  if (BINARY_EXT.has(ext)) return true;
  const head = buffer.subarray(0, Math.min(buffer.length, 8192));
  return head.includes(0);
}

function scan() {
  const args = collectArgs(process.argv.slice(2));
  if (args.error) {
    console.error(`usage: node tools/check-no-secrets.mjs [--root <dir>]... (${args.error})`);
    process.exit(2);
  }

  const hits = [];
  let filesScanned = 0;

  for (const root of args.roots) {
    const targets = [];
    for (const dir of SCAN_DIRS) listFiles(join(root, dir), targets);

    for (const path of targets) {
      let stat;
      try { stat = statSync(path); } catch { continue; }
      if (stat.size > MAX_FILE_BYTES) continue;
      let buffer;
      try { buffer = readFileSync(path); } catch { continue; }
      if (isProbablyBinary(path, buffer)) continue;
      filesScanned++;

      const rel = relative(root, path) || path;
      const inFixtures = rel.split(sep)[0] === "fixtures";
      const text = buffer.toString("utf8");
      const lowerName = path.split(sep).pop().toLowerCase();

      // real-looking GoogleService configs anywhere; inside fixtures only fake-marked ones pass
      if (GOOGLE_SERVICE_FILES.has(lowerName)) {
        const fakeMarked = FAKE_MARKER.test(text);
        if (!inFixtures || !fakeMarked) {
          hits.push(`google-service-config  ${rel} (no obvious fake markers inside)`);
        }
      }

      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const [name, re, fakeGroup] of VALUE_PATTERNS) {
          const match = re.exec(line);
          if (!match) continue;
          const suspect = fakeGroup ? (match[fakeGroup] ?? "") : match[0];
          if (FAKE_MARKER.test(suspect)) continue;
          hits.push(`${name.padEnd(22)} ${rel}:${i + 1}  ${redact(suspect)}`);
        }
        if (PRIVATE_KEY_RE.test(line)) {
          const fileFake = inFixtures && FAKE_MARKER.test(text);
          if (!(inFixtures && fileFake)) {
            hits.push(`private-key          ${rel}:${i + 1}`);
          }
        }
      }
    }
  }

  if (hits.length) {
    console.error(`SECRET CHECK FAILED — ${hits.length} hit(s):`);
    for (const hit of hits) console.error(`  ${hit}`);
    console.error("Real-looking credentials must never be committed. Use sandbox-fake values (see fixtures/).");
    process.exit(1);
  }
  console.log(`OK: no secrets found in ${filesScanned} scanned files`);
}

function redact(suspect) {
  const s = String(suspect);
  return s.length <= 12 ? `"${s}"` : `"${s.slice(0, 8)}…<redacted ${s.length - 8} chars>"`;
}

scan();
