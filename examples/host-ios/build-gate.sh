#!/bin/sh
# The one gate for the iOS embedding host: (1) build the demo bundle, (2) copy
# it into ./nsh, (3) xcodebuild against the nsh-auth simulator. Any error
# fails the gate. Idempotent; safe to re-run.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SIM_UDID="DEE48BA7-1919-47BC-A04A-887B6D2AB046" # simulator "nsh-auth" — the only device this repo may touch
APP="$SCRIPT_DIR/build/derived/Build/Products/Debug-iphonesimulator/NshAuthSandbox.app"

# 1 + 2. Demo build and bundle copy (fresh every gate run).
"$SCRIPT_DIR/scripts/demo-bundle.sh" --force

# 3. The app build. Ad-hoc signing only: simulator, no team, no entitlements.
xcodebuild \
    -project "$SCRIPT_DIR/NshAuthHostIOS.xcodeproj" \
    -scheme NshAuthSandbox \
    -configuration Debug \
    -destination "id=$SIM_UDID" \
    -derivedDataPath "$SCRIPT_DIR/build/derived" \
    build

[ -d "$APP" ] || { echo "gate failed: no app at $APP" >&2; exit 1; }
[ -f "$APP/nsh/bundle.nshc" ] || { echo "gate failed: nsh/bundle.nshc missing from the app bundle" >&2; exit 1; }
plutil -extract CFBundleURLTypes.0.CFBundleURLSchemes.0 raw "$APP/Info.plist" | grep -qx 'nsh.auth.sandbox' \
    || { echo "gate failed: URL scheme nsh.auth.sandbox not registered" >&2; exit 1; }
if grep -rl 'client_secret' "$APP" 2>/dev/null; then
    echo "gate failed: client_secret found in the app bundle" >&2
    exit 1
fi

echo "gate passed: $APP"
