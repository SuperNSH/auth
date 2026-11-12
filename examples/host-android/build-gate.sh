#!/usr/bin/env bash
# Gate for examples/host-android: build the demo bundle with the demo's own
# documented command, embed it as APK assets, then build the host APK with
# Gradle. Fails on the first error; safe to re-run.
set -euo pipefail

cd "$(dirname "$0")"

export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
# The upstream installer's ~/.nsh/bin comes before Homebrew, whose nsh is still 0.4.0.
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$HOME/.nsh/bin:$BREW_PREFIX/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

[ -x "$JAVA_HOME/bin/java" ] || { echo "error: Android Studio JBR not found at $JAVA_HOME" >&2; exit 1; }
[ -d "$ANDROID_HOME" ] || { echo "error: Android SDK not found at $ANDROID_HOME" >&2; exit 1; }
command -v nsh >/dev/null || { echo "error: nsh is not on PATH (need 0.5.0)" >&2; exit 1; }
case "$(nsh --version)" in
    "nsh 0.5.0"*) ;;
    *) echo "error: need nsh 0.5.0 (upstream installer, ~/.nsh/bin); $(command -v nsh) is $(nsh --version)" >&2; exit 1 ;;
esac
[ -f gradle/wrapper/gradle-wrapper.jar ] || { echo "error: gradle/wrapper/gradle-wrapper.jar is missing" >&2; exit 1; }
[ -x ./gradlew ] || chmod +x ./gradlew

# AGP reads the SDK path from here; machine-local, gitignored.
echo "sdk.dir=$ANDROID_HOME" > local.properties

# The nsh AARs are not vendored in the repository; copy the pinned 0.5.0 pair.
# tools/fetch-nsh-embed.sh downloads nsh-embed-android.zip from the v0.5.0
# release once, sha256-checked, into the git-ignored .nsh-embed/0.5.0/android.
# Set NSH_EMBED_ANDROID to use AARs from elsewhere.
NSH_EMBED="${NSH_EMBED_ANDROID:-$(../../tools/fetch-nsh-embed.sh android)}"
[ -f "$NSH_EMBED/nsh.aar" ] || { echo "error: $NSH_EMBED/nsh.aar not found" >&2; exit 1; }
[ -f "$NSH_EMBED/nsh-dev.aar" ] || { echo "error: $NSH_EMBED/nsh-dev.aar not found" >&2; exit 1; }
mkdir -p app/libs
cp -f "$NSH_EMBED/nsh.aar" app/libs/nsh.aar
cp -f "$NSH_EMBED/nsh-dev.aar" app/libs/nsh-dev.aar

DEMO_DIR="$(cd .. && pwd)/demo"
[ -d "$DEMO_DIR" ] || { echo "error: examples/demo does not exist yet" >&2; exit 1; }

# The demo's documented embed command: in a fenced README block, the line
# naming host-android (the demo documents iOS and Android embeds side by side
# and lists an unrelated debug `nsh build` earlier), else the first `nsh build`
# line, else the standard release build. Keep in sync with the same logic in
# app/build.gradle.kts (the Gradle task embeds a fresh bundle on a bare
# ./gradlew run too).
DEMO_CMD="$(awk '
    /^[[:space:]]*```/ { inblock = !inblock; next }
    inblock && /nsh build/ {
        if ($0 ~ /host-android/) { print; found = 1; exit }
        if (first == "") first = $0
    }
    END { if (!found && first != "") print first }
' "$DEMO_DIR/README.md" 2>/dev/null || true)"
DEMO_CMD="${DEMO_CMD:-nsh build --release}"

# 1. Build the demo bundle (its output lands wherever the demo documents,
#    default .nsh/out).
echo "== demo bundle: $DEMO_CMD (cwd $DEMO_DIR)"
MARK="$(mktemp)"
(cd "$DEMO_DIR" && bash -c "$DEMO_CMD")

# 2. Embed the freshest bundle produced by that run as app/src/main/assets/nsh.
#    Freshness is compared in whole seconds (`-nt` misses a build that lands in
#    the same second as MARK); a bundle from before the run is still excluded.
ASSETS_NSH="app/src/main/assets/nsh"
MARK_MTIME="$(stat -f %m "$MARK")"
BUNDLE="$(find "$DEMO_DIR" \( -name node_modules -o -name .git -o -name .gradle \) -prune -o \
    -name bundle.nshc -print 2>/dev/null \
    | while IFS= read -r f; do
        m="$(stat -f %m "$f")"
        if [ "$m" -ge "$MARK_MTIME" ]; then printf '%s\t%s\n' "$m" "$f"; fi
      done \
    | sort -k1,1rn -k2,2 | head -1 | cut -f2-)"
if [ -z "$BUNDLE" ]; then
  # The demo command may target the assets directory directly.
  if [ -f "$ASSETS_NSH/bundle.nshc" ] && [ "$(stat -f %m "$ASSETS_NSH/bundle.nshc")" -ge "$MARK_MTIME" ]; then
    echo "== bundle already embedded at $ASSETS_NSH"
  else
    echo "error: the demo build produced no bundle.nshc under examples/demo" >&2
    rm -f "$MARK"
    exit 1
  fi
else
  BUNDLE_DIR="$(dirname "$BUNDLE")"
  rm -rf "$ASSETS_NSH"
  mkdir -p "$ASSETS_NSH"
  cp -R "$BUNDLE_DIR/." "$ASSETS_NSH/"
  echo "== embedded $(basename "$BUNDLE_DIR") -> $ASSETS_NSH"
fi
rm -f "$MARK"

# 3. Build the host APK (preBuild re-verifies libs and embeds a fresh bundle).
./gradlew assembleDebug

echo "== APK: $PWD/app/build/outputs/apk/debug/app-debug.apk"
