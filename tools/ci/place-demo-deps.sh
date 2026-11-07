#!/usr/bin/env bash
# Places the two sibling libraries the demo imports under examples/demo/node_modules,
# the layout the demo README builds with symlinks. CI clones each library's default
# branch, installs the dependencies its package.json declares, and copies the package
# so the same path works on Windows runners. Run from anywhere inside the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${RUNNER_TEMP:-$(mktemp -d)}"
NODE_MODULES="$ROOT/examples/demo/node_modules"

mkdir -p "$NODE_MODULES"
rm -rf "$NODE_MODULES/nsh-auth"
cp -R "$ROOT/packages/nsh-auth" "$NODE_MODULES/nsh-auth"

for lib in form query; do
    git clone --quiet --depth 1 "https://github.com/SuperNSH/$lib.git" "$WORK/nsh-$lib"
    pkg="$WORK/nsh-$lib/packages/nsh-$lib"
    (cd "$pkg" && npm install --no-audit --no-fund --package-lock=false)
    rm -rf "$NODE_MODULES/nsh-$lib"
    cp -R "$pkg" "$NODE_MODULES/nsh-$lib"
done

ls "$NODE_MODULES"
