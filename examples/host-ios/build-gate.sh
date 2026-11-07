#!/bin/sh
# The one gate for the iOS embedding host: (1) build the demo bundle and copy
# it into ./nsh, (2) unit-assert the pure sign-in math, (3) xcodebuild against
# the nsh-auth simulator, (4) check the built app (bundle presence, URL
# schemes, entitlements, no-secret greps). Any error fails the gate. Idempotent;
# safe to re-run.
#
# SPM: the project now resolves GoogleSignIn 10.1.0 and facebook-ios-sdk
# 19.0.1, so the build needs NETWORK (github.com) for package resolution —
# not hermetic anymore, accepted for phase 3. The two-step story:
#   1. Bootstrap (once per clean clone): resolve without the pinning flag,
#      e.g.  xcodebuild -project NshAuthHostIOS.xcodeproj \
#        -scheme NshAuthSandbox -resolvePackageDependencies -derivedDataPath build/derived
#      which writes project.xcworkspace/xcshareddata/swiftpm/Package.resolved
#      (checked into git).
#   2. Pinned (every gate run, as below): -resolvePackageDependencies +
#      -onlyUsePackageVersionsFromResolvedFile, so versions can never drift
#      from Package.resolved. Delete Package.resolved to re-bootstrap.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIM_UDID="DEE48BA7-1919-47BC-A04A-887B6D2AB046" # simulator "nsh-auth" — the only device this repo may touch
APP="$SCRIPT_DIR/build/derived/Build/Products/Debug-iphonesimulator/NshAuthSandbox.app"
RESOLVED="$SCRIPT_DIR/NshAuthHostIOS.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"

# 1. Demo build and bundle copy (fresh every gate run).
"$SCRIPT_DIR/scripts/demo-bundle.sh" --force

# 2. Unit asserts for the pure sign-in math (epoch-ms conversion, SHA-256).
"$SCRIPT_DIR/../../native/ios/tests/auth-signin-math-test.sh"

# 3. The app build, in two xcodebuild steps: resolution (pinned to the
# committed Package.resolved — versions can never drift) and the build itself
# (passing -resolvePackageDependencies to a build makes this xcodebuild
# resolve and exit WITHOUT building, so the flags cannot be merged).
# Ad-hoc signing: simulator, no team; the entitlements file (Sign in with
# Apple) is embedded by CODE_SIGN_ENTITLEMENTS in the pbxproj. The
# hand-written pbxproj declares no build-phase inputs, so Xcode 27's
# incremental build skips INFOPLIST_FILE reprocessing and entitlements/signing
# regeneration when settings change; the gate wipes the target's intermediates
# and product so every step reruns against current project settings (compile
# objects for the Swift files are rebuilt — seconds, not minutes).
[ -f "$RESOLVED" ] || { echo "gate failed: no Package.resolved at $RESOLVED; run the bootstrap resolve documented in this script's header" >&2; exit 1; }
TARGET_INTERMEDIATES="$SCRIPT_DIR/build/derived/Build/Intermediates.noindex/NshAuthHostIOS.build/Debug-iphonesimulator/NshAuthSandbox.build"
rm -rf "$APP" "$TARGET_INTERMEDIATES"
xcodebuild \
    -project "$SCRIPT_DIR/NshAuthHostIOS.xcodeproj" \
    -scheme NshAuthSandbox \
    -configuration Debug \
    -destination "id=$SIM_UDID" \
    -derivedDataPath "$SCRIPT_DIR/build/derived" \
    -onlyUsePackageVersionsFromResolvedFile \
    -resolvePackageDependencies
xcodebuild \
    -project "$SCRIPT_DIR/NshAuthHostIOS.xcodeproj" \
    -scheme NshAuthSandbox \
    -configuration Debug \
    -destination "id=$SIM_UDID" \
    -derivedDataPath "$SCRIPT_DIR/build/derived" \
    -onlyUsePackageVersionsFromResolvedFile \
    build

# 4. Built-app checks.
[ -d "$APP" ] || { echo "gate failed: no app at $APP" >&2; exit 1; }
[ -f "$APP/nsh/bundle.nshc" ] || { echo "gate failed: nsh/bundle.nshc missing from the app bundle" >&2; exit 1; }
plutil -extract CFBundleURLTypes.0.CFBundleURLSchemes.0 raw "$APP/Info.plist" | grep -qx 'nsh.auth.sandbox' \
    || { echo "gate failed: URL scheme nsh.auth.sandbox not registered" >&2; exit 1; }
plutil -extract CFBundleURLTypes.1.CFBundleURLSchemes.0 raw "$APP/Info.plist" | grep -qx 'com.googleusercontent.apps.nsh-auth-sandbox' \
    || { echo "gate failed: reversed Google client-id scheme not registered" >&2; exit 1; }
plutil -extract CFBundleURLTypes.2.CFBundleURLSchemes.0 raw "$APP/Info.plist" | grep -qx 'fb1234567890123456' \
    || { echo "gate failed: URL scheme fb1234567890123456 not registered" >&2; exit 1; }
# Xcode 26+ (iOS 27 SDK): simulator signing sets ENTITLEMENTS_ALLOWED=NO, so
# `codesign -d --entitlements` reports an empty plist; the app entitlements are
# instead linked into the executable's __TEXT,__entitlements section (and the
# signature's DER blob), which is what the simulator consults at runtime.
grep -q 'com.apple.developer.applesignin' "$APP/NshAuthSandbox" \
    || { echo "gate failed: com.apple.developer.applesignin not embedded in the app executable" >&2; exit 1; }
# No embedded secret VALUE. With the SDKs linked, "client_secret" also exists
# as a bare parameter-name constant inside AppAuth/GTMAppAuth/GoogleSignIn
# (verified: the strings are the OAuth param list and a null-terminated
# "client_secret=" URL builder), so both scans anchor on an assigned value
# instead of the name. Forms covered: url/query assignment, double- and
# single-quoted assignment (JSON/shell), and plist key/value pairs where key
# and value sit on separate lines. Every .plist in the built app is an Apple
# BINARY property list, so the plist scan converts each file to XML text with
# plutil (cat fallback for non-plist .xml/.entitlements); the same helper runs
# in the self-test and the real scan — the tested path is the shipped path.
SECRET_LINE_PAT="client_secret[\"']?[[:space:]]*[=:][[:space:]]*['\"]?[A-Za-z0-9._~-]{8,}"
SECRET_XML_PAT='<string>[^<]*[A-Za-z0-9._~-]{8,}[^<]*</string>'
SECRET_VALUE="planted-secret-value-42"

# Stdin: NUL-separated file paths. Stdout: the client_secret value lines that
# match the pattern, if any.
plist_secret_hits() {
    while IFS= read -r -d '' f; do
        plutil -convert xml1 -o - "$f" 2>/dev/null || cat "$f"
    done | grep -A1 '<key>client_secret</key>' | grep -E "$SECRET_XML_PAT"
}

SELFTEST=$(mktemp -d)
trap 'rm -rf "$SELFTEST"' EXIT
printf 'x=1&client_secret=%s&grant_type=x\n' "$SECRET_VALUE" > "$SELFTEST/query.txt"
printf '"client_secret": "%s"\n' "$SECRET_VALUE" > "$SELFTEST/double-quoted.json"
printf "'client_secret': '%s'\n" "$SECRET_VALUE" > "$SELFTEST/single-quoted.txt"
printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n<key>client_secret</key>\n<string>%s</string>\n</dict></plist>\n' "$SECRET_VALUE" > "$SELFTEST/textual.plist"
plutil -convert binary1 -o "$SELFTEST/binary.plist" "$SELFTEST/textual.plist"
printf 'client_id=x&redirect_uri=y&client_secret=\n' > "$SELFTEST/sdk-constant.txt"
grep -Eq "$SECRET_LINE_PAT" "$SELFTEST/query.txt" \
    || { echo "gate failed: secret scan self-test missed the url/query form" >&2; exit 1; }
grep -Eq "$SECRET_LINE_PAT" "$SELFTEST/double-quoted.json" \
    || { echo "gate failed: secret scan self-test missed the double-quoted form" >&2; exit 1; }
grep -Eq "$SECRET_LINE_PAT" "$SELFTEST/single-quoted.txt" \
    || { echo "gate failed: secret scan self-test missed the single-quoted form" >&2; exit 1; }
find "$SELFTEST/textual.plist" -print0 | plist_secret_hits | grep -q . \
    || { echo "gate failed: secret scan self-test missed the textual plist form" >&2; exit 1; }
find "$SELFTEST/binary.plist" -print0 | plist_secret_hits | grep -q . \
    || { echo "gate failed: secret scan self-test missed the BINARY plist form" >&2; exit 1; }
grep -Eq "$SECRET_LINE_PAT" "$SELFTEST/sdk-constant.txt" \
    && { echo "gate failed: secret scan self-test false-positives on the bare SDK constant" >&2; exit 1; }

if grep -rEq "$SECRET_LINE_PAT" "$APP" 2>/dev/null; then
    echo "gate failed: an embedded client_secret value was found in the app bundle" >&2
    exit 1
fi
find "$APP" -type f \( -name '*.plist' -o -name '*.entitlements' -o -name '*.xml' \) -print0 \
    | plist_secret_hits | grep -q . \
    && { echo "gate failed: a plist-embedded client_secret value was found in the app bundle" >&2; exit 1; }

echo "gate passed: $APP"
