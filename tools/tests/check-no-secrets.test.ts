import { describe, test, expect, afterAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const scanner = fileURLToPath(new URL("../check-no-secrets.mjs", import.meta.url));
const toolsDir = fileURLToPath(new URL("..", import.meta.url));
const tempRoots: string[] = [];

// planted-secret scratch repos live under tools/ per the task contract; the
// scanner's default root never scans tools/, so these cannot self-trigger.
function makeTempRepo(): string {
  const root = mkdtempSync(join(toolsDir, ".tmp-nsh-secrets-"));
  tempRoots.push(root);
  return root;
}

function runScanner(root: string) {
  const res = spawnSync(process.execPath, [scanner, "--root", root], { encoding: "utf8" });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

// planted secret formats that must trip the gate
const REAL_CLIENT_SECRET = `client_secret: "GyaR4skR3alL00kingCredentialValue1"`;
const REAL_GOOGLE_CLIENT_ID = "482155163272-8f7abcde1234567890abcdef12345678.apps.googleusercontent.com";
const REAL_GH_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIBCgKCAQEA1234\n-----END RSA PRIVATE KEY-----";

afterAll(() => {
  for (const root of tempRoots) rmSync(root, { recursive: true, force: true });
});

describe("check-no-secrets smoke gate", () => {
  test("a clean tree passes with exit 0", () => {
    const root = makeTempRepo();
    mkdirSync(join(root, "packages", "app", "src"), { recursive: true });
    writeFileSync(join(root, "packages", "app", "src", "auth.ts"), 'client_id: "nsh-auth-sandbox.apps.googleusercontent.com"\n');
    mkdirSync(join(root, "fixtures"), { recursive: true });
    writeFileSync(join(root, "fixtures", "mock-google.json"), 'client_secret: "FAKE-nsh-sandbox-secret-value"\n');
    const res = runScanner(root);
    expect(res.code).toBe(0);
    expect(res.stdout).toMatch(/OK: no secrets found/);
  });

  test("a planted client_secret fails the gate with a located hit", () => {
    const root = makeTempRepo();
    mkdirSync(join(root, "packages", "app", "src"), { recursive: true });
    writeFileSync(join(root, "packages", "app", "src", "config.ts"), `const cfg = {\n  ${REAL_CLIENT_SECRET},\n};\n`);
    const res = runScanner(root);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("client_secret-literal");
    expect(res.stderr).toContain(join("packages", "app", "src", "config.ts") + ":2");
  });

  test("real-looking Google client id and GitHub token fail the gate", () => {
    const root = makeTempRepo();
    mkdirSync(join(root, "crates", "auth", "src"), { recursive: true });
    writeFileSync(join(root, "crates", "auth", "src", "ids.rs"), `const ID = "${REAL_GOOGLE_CLIENT_ID}";\nconst TK = "${REAL_GH_TOKEN}";\n`);
    const res = runScanner(root);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("google-client-id");
    expect(res.stderr).toContain("github-token");
  });

  test("a real-looking google-services.json in example build output fails; the same fake-marked file under fixtures/ passes", () => {
    // no pattern-recognizable token inside: the FILENAME rule is what must catch it
    const realish = JSON.stringify({
      project_info: { project_number: "482155163272", project_id: "real-prod-app" },
      client: [{ client_info: { mobilesdk_app_id: "1:482155163272:android:abc123" } }],
    });
    const root = makeTempRepo();
    const buildDir = join(root, "examples", "demo", "build");
    mkdirSync(buildDir, { recursive: true });
    writeFileSync(join(buildDir, "google-services.json"), realish);
    expect(runScanner(root).code).toBe(1);

    const root2 = makeTempRepo();
    const fixturesDir = join(root2, "fixtures");
    mkdirSync(fixturesDir, { recursive: true });
    writeFileSync(
      join(fixturesDir, "google-services.json"),
      JSON.stringify({ project_info: { project_id: "nsh-auth-sandbox-example" }, _comment: "FAKE sandbox fixture" }),
    );
    const res2 = runScanner(root2);
    expect(res2.code).toBe(0);
  });

  test("a secret pasted into example SOURCE (not just build output) fails the gate", () => {
    const root = makeTempRepo();
    const srcDir = join(root, "examples", "demo", "src");
    mkdirSync(srcDir, { recursive: true });
    writeFileSync(
      join(srcDir, "github-config.ts"),
      `export const githubClientSecret = "client_secret: '8xR3alL00kingSecretPastedInDemo99'";\n`,
    );
    const res = runScanner(root);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("client_secret-literal");
    expect(res.stderr).toContain(join("examples", "demo", "src", "github-config.ts") + ":1");
  });

  test("SPM checkouts (examples/**/build/derived/SourcePackages) are skipped; the same secret in project-authored trees still fails", () => {
    const root = makeTempRepo();
    // upstream-shaped false positives: an SDK test fixture with its own app secret
    // and a sample-app plist with the vendor's client id, as checked out by Xcode
    const checkoutDir = join(root, "examples", "host-ios", "build", "derived", "SourcePackages", "checkouts", "facebook-ios-sdk", "FBSDKCoreKitTests");
    mkdirSync(checkoutDir, { recursive: true });
    writeFileSync(join(checkoutDir, "CrashObserverFixture.plist"), REAL_CLIENT_SECRET + "\n");
    writeFileSync(join(checkoutDir, "SignInSample-Info.plist"), `CLIENT_ID = ${REAL_GOOGLE_CLIENT_ID};\n`);

    // control 1: derived build output authored by the project (the app bundle) stays scanned
    const appBundleDir = join(root, "examples", "host-ios", "build", "derived", "Build", "Products", "Host.app");
    mkdirSync(appBundleDir, { recursive: true });
    writeFileSync(join(appBundleDir, "auth-config.plist"), REAL_CLIENT_SECRET + "\n");
    // control 2: a SourcePackages dir NOT under examples/**/build/derived stays scanned
    const localPackagesDir = join(root, "examples", "host-ios", "SourcePackages", "checkouts", "our-kit");
    mkdirSync(localPackagesDir, { recursive: true });
    writeFileSync(join(localPackagesDir, "config.plist"), REAL_CLIENT_SECRET + "\n");
    // control 3: example source stays scanned
    const srcDir = join(root, "examples", "host-ios", "Host", "src");
    mkdirSync(srcDir, { recursive: true });
    writeFileSync(join(srcDir, "config.ts"), REAL_CLIENT_SECRET + "\n");

    const res = runScanner(root);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("client_secret-literal");
    expect(res.stderr).toContain(join("examples", "host-ios", "build", "derived", "Build", "Products", "Host.app", "auth-config.plist") + ":1");
    expect(res.stderr).toContain(join("examples", "host-ios", "SourcePackages", "checkouts", "our-kit", "config.plist") + ":1");
    expect(res.stderr).toContain(join("examples", "host-ios", "Host", "src", "config.ts") + ":1");
    expect(res.stderr).not.toContain(join("examples", "host-ios", "build", "derived", "SourcePackages"));
  });

  test("a private key in native/ fails; a fake-marked one under fixtures/ passes", () => {
    const root = makeTempRepo();
    const nativeDir = join(root, "native", "ios", "Signing");
    mkdirSync(nativeDir, { recursive: true });
    writeFileSync(join(nativeDir, "Key.p8"), PRIVATE_KEY + "\n");
    expect(runScanner(root).code).toBe(1);

    const root2 = makeTempRepo();
    const fixturesDir = join(root2, "fixtures");
    mkdirSync(fixturesDir, { recursive: true });
    writeFileSync(join(fixturesDir, "test-signing-key.pem"), `// FAKE sandbox test key\n${PRIVATE_KEY}\n`);
    expect(runScanner(root2).code).toBe(0);
  });

  test("numeric client ids that look real fail; sandbox-marked ones pass", () => {
    const root = makeTempRepo();
    mkdirSync(join(root, "packages", "app", "src"), { recursive: true });
    writeFileSync(join(root, "packages", "app", "src", "discord.json"), JSON.stringify({ client_id: "1098765432109876543" }));
    const res = runScanner(root);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("numeric-client-id");
  });

  test("binary files are skipped, not false positives", () => {
    const root = makeTempRepo();
    const assetDir = join(root, "packages", "app", "assets");
    mkdirSync(assetDir, { recursive: true });
    // PNG magic followed by an embedded plaintext secret: the binary skip keeps it quiet
    const png = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]),
      Buffer.from("client_secret: 'GOCSPX-embeddedinbinary99'"),
    ]);
    writeFileSync(join(assetDir, "icon.png"), png);
    writeFileSync(join(assetDir, "notes.txt"), "client_secret: 'GOCSPX-purelytextualhit12'"); // not fake-marked -> hit
    const res = runScanner(root);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("notes.txt");
    expect(res.stderr).not.toContain("icon.png:");
  });

  test("missing --root usage error exits 2", () => {
    const res = spawnSync(process.execPath, [scanner, "--bogus"], { encoding: "utf8" });
    expect(res.status).toBe(2);
  });
});
