#!/usr/bin/env bash
# Places the two sibling libraries the demo imports under examples/demo/node_modules,
# the layout the demo README builds with symlinks. CI copies instead of linking so the
# result is identical on Windows runners. Run from anywhere inside the repo.
#
# The libraries are pinned to the commits the demo was verified against. Their default
# branches have since moved on (new @tanstack dependencies and a changed query API), and
# the demo does not compile against those.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${RUNNER_TEMP:-$(mktemp -d)}"
NODE_MODULES="$ROOT/examples/demo/node_modules"

NSH_FORM_SHA=682844a08bb5de5b5a0d196d8ea383cce7dcba2b
NSH_QUERY_SHA=470e10a49f0e4e44148a6a08e229a55867eb9688

mkdir -p "$NODE_MODULES"
rm -rf "$NODE_MODULES/nsh-auth" "$NODE_MODULES/nsh-form" "$NODE_MODULES/nsh-query"
cp -R "$ROOT/packages/nsh-auth" "$NODE_MODULES/nsh-auth"

for pin in "form $NSH_FORM_SHA" "query $NSH_QUERY_SHA"; do
    set -- $pin
    lib=$1
    sha=$2
    git clone --quiet "https://github.com/SuperNSH/$lib.git" "$WORK/nsh-$lib"
    git -C "$WORK/nsh-$lib" checkout --quiet "$sha"
    cp -R "$WORK/nsh-$lib/packages/nsh-$lib" "$NODE_MODULES/nsh-$lib"
done

ls "$NODE_MODULES"
