#!/bin/sh
# Builds the demo app (examples/demo) and places its bundle output into ./nsh,
# the folder reference the app embeds. The command documented in
# examples/demo/README.md wins when its README exists; otherwise the standard
# `nsh build --release --out <dir>` from nsh 0.4.0 examples/embed-ios runs.
# Stamp-based: a rebuild is skipped while the bundle is newer than the demo
# sources. `--force` rebuilds (build-gate.sh always passes it).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# xcodebuild runs phases with a minimal PATH; Homebrew is not on it.
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
HOST_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$HOST_DIR/../.." && pwd)
DEMO_DIR="$REPO_ROOT/examples/demo"
OUT_DIR="$HOST_DIR/nsh"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

[ -d "$DEMO_DIR" ] || { echo "demo-bundle: $DEMO_DIR does not exist" >&2; exit 1; }

if [ "$FORCE" -eq 0 ] && [ -f "$OUT_DIR/bundle.nshc" ]; then
    changed=$(find "$DEMO_DIR" -type f -not -path '*/node_modules/*' -newer "$OUT_DIR/bundle.nshc" -print -quit 2>/dev/null || true)
    [ -z "$changed" ] && { echo "demo bundle up to date: $OUT_DIR"; exit 0; }
fi

# First `nsh build` line inside a fenced code block, joined across "\"
# continuations. An embed build names an --out; a bare `nsh build` (a gates
# example) only wins when no --out line exists.
cmd=$(awk '
    /^```/ { inblock = !inblock; next }
    !inblock { next }
    collecting {
        sub(/\\[ \t]*$/, "", buf)
        buf = buf " " $0
        if ($0 !~ /\\[ \t]*$/) { print buf; exit }
        next
    }
    index($0, "nsh build") {
        if ($0 ~ /\\[ \t]*$/) { buf = $0; collecting = 1 }
        else { print $0; exit }
    }
' "$DEMO_DIR/README.md" 2>/dev/null || true)
cmd_out=$(awk '
    /^```/ { inblock = !inblock; next }
    !inblock { next }
    index($0, "nsh build") && index($0, "--out") { print; exit }
' "$DEMO_DIR/README.md" 2>/dev/null || true)
[ -n "$cmd_out" ] && cmd=$cmd_out

if [ -n "$cmd" ]; then
    # Strip markdown dressing and an inline comment.
    cmd=$(printf '%s' "$cmd" | sed -E 's/`//g; s/^[[:space:]]*[-*>$[:space:]]+//; s/[[:space:]]+#[^#]*$//')
fi

copied_from=""
if [ -n "$cmd" ]; then
    if printf '%s' "$cmd" | grep -q -- '--out'; then
        # Verbatim documented command; its own --out target is copied into ./nsh.
        out=$(printf '%s' "$cmd" | sed -E 's/.*--out[[:space:]]+"?([^"[:space:]]+)"?.*/\1/')
        echo "demo-bundle: documented command: $cmd"
        (cd "$DEMO_DIR" && eval "$cmd")
        case "$out" in
            /*) src_out=$out ;;
            *) src_out="$DEMO_DIR/$out" ;;
        esac
        if [ "$(cd -- "$src_out" && pwd)" != "$OUT_DIR" ]; then
            rm -rf "$OUT_DIR"
            mkdir -p "$OUT_DIR"
            ditto "$src_out" "$OUT_DIR"
            copied_from=$src_out
        fi
    else
        cmd="$cmd --out \"\$OUT_DIR\""
        echo "demo-bundle: documented command (with --out added): $cmd"
        (cd "$DEMO_DIR" && eval "$cmd")
    fi
else
    echo "demo-bundle: no documented command in examples/demo/README.md; running standard nsh build"
    (cd "$DEMO_DIR" && nsh build --release --out "$OUT_DIR")
fi

[ -f "$OUT_DIR/bundle.nshc" ] || { echo "demo-bundle: bundle.nshc missing from $OUT_DIR" >&2; exit 1; }
echo "demo-bundle: bundle ready in $OUT_DIR${copied_from:+ (copied from $copied_from)}"
