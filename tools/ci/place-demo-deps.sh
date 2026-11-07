#!/usr/bin/env bash
# Places the two sibling libraries the demo imports under examples/demo/node_modules,
# the layout the demo README builds with symlinks. CI copies instead of linking so the
# result is identical on Windows runners. Run from anywhere inside the repo.
#
# The siblings are cloned from their default branches: master carries the
# TanStack-based API the demo uses. Their declared dependencies (@tanstack/query-core,
# @tanstack/form-core and friends) are installed with bun inside the clones and copied
# flat into the demo's node_modules, because the demo's own manifest does not declare them.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${RUNNER_TEMP:-$(mktemp -d)}"
NODE_MODULES="$ROOT/examples/demo/node_modules"

mkdir -p "$NODE_MODULES"
rm -rf "$NODE_MODULES/nsh-auth" "$NODE_MODULES/nsh-form" "$NODE_MODULES/nsh-query" "$NODE_MODULES/@tanstack"

cp -R "$ROOT/packages/nsh-auth" "$NODE_MODULES/nsh-auth"

for lib in form query; do
    git clone --quiet "https://github.com/SuperNSH/$lib.git" "$WORK/nsh-$lib"
    (cd "$WORK/nsh-$lib" && bun install)
    cp -R "$WORK/nsh-$lib/packages/nsh-$lib" "$NODE_MODULES/nsh-$lib"
    if [ -d "$WORK/nsh-$lib/node_modules" ]; then
        cp -R "$WORK/nsh-$lib/node_modules/." "$NODE_MODULES/"
    fi
done

ls "$NODE_MODULES"
