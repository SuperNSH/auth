#!/usr/bin/env bash
# Places the two sibling libraries the demo imports under examples/demo/node_modules,
# the same layout the demo README builds with symlinks. CI copies instead of linking
# so the result is identical on Windows runners. Run from anywhere inside the repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${RUNNER_TEMP:-$(mktemp -d)}"
NODE_MODULES="$ROOT/examples/demo/node_modules"

for lib in form query; do
    git clone --quiet --depth 1 "https://github.com/SuperNSH/$lib.git" "$WORK/nsh-$lib"
done

mkdir -p "$NODE_MODULES"
rm -rf "$NODE_MODULES/nsh-auth" "$NODE_MODULES/nsh-form" "$NODE_MODULES/nsh-query"
cp -R "$ROOT/packages/nsh-auth" "$NODE_MODULES/nsh-auth"
cp -R "$WORK/nsh-form/packages/nsh-form" "$NODE_MODULES/nsh-form"
cp -R "$WORK/nsh-query/packages/nsh-query" "$NODE_MODULES/nsh-query"
ls "$NODE_MODULES"
