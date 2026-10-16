#!/bin/sh
# Re-copy the pinned upstream uQUIC into native/third_party/uquic, restore our
# added files, re-apply our patches, and rebuild the engines.
#
# Usage: tools/rebase_uquic.sh [version]
#   version defaults to the one pinned in native/go.mod.
#
# Our added files (new files only; upstream files are never edited except via
# patches/) are listed in OURS below and are preserved across the rebase.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
NATIVE="$ROOT/native"
FORK="$NATIVE/third_party/uquic"

# Files that are ours (not from upstream) and must survive a rebase.
OURS="FORK.md u_server_hello.go \
internal/handshake/freetls_evp_ccm.go \
internal/handshake/freetls_evp_ccm_stub.go \
internal/handshake/freetls_evp_ccm_test.go \
internal/handshake/freetls_evp_ccm_stub_test.go \
internal/handshake/freetls_server_hello.go"

find_go() {
    for cand in "${FREETLS_GO:-}" go "$HOME/.local/go/bin/go" \
        /usr/local/go/bin/go /opt/go/bin/go; do
        [ -n "$cand" ] || continue
        if [ -x "$cand" ]; then printf '%s\n' "$cand"; return 0; fi
        if command -v "$cand" >/dev/null 2>&1; then command -v "$cand"; return 0; fi
    done
    echo "Go toolchain not found; set FREETLS_GO=/path/to/go" >&2
    return 1
}

GO=$(find_go)
PATH="$(dirname "$GO"):$PATH"
export PATH

if [ "${1:-}" != "" ]; then
    VER="$1"
else
    VER=$(sed -n 's/.*github.com\/refraction-networking\/uquic \(v[^ ]*\).*/\1/p' "$NATIVE/go.mod" | head -1)
fi
[ -n "$VER" ] || { echo "could not determine pinned uQUIC version" >&2; exit 1; }
echo "[rebase] pinned uQUIC version: $VER"

GOMODCACHE=$(cd "$NATIVE" && "$GO" env GOMODCACHE)
UPSTREAM="$GOMODCACHE/github.com/refraction-networking/uquic@$VER"
if [ ! -d "$UPSTREAM" ]; then
    echo "[rebase] downloading $VER into the module cache"
    (cd "$NATIVE" && "$GO" mod download "github.com/refraction-networking/uquic@$VER")
fi
[ -d "$UPSTREAM" ] || { echo "upstream module not found at $UPSTREAM" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
for f in $OURS; do
    if [ -e "$FORK/$f" ]; then
        mkdir -p "$STAGE/$(dirname "$f")"
        cp -a "$FORK/$f" "$STAGE/$f"
    fi
done
# The patch set is ours too; preserve it across the re-copy.
if [ -d "$FORK/patches" ]; then cp -a "$FORK/patches" "$STAGE/patches"; fi

mkdir -p "$FORK"
find "$FORK" -mindepth 1 -delete
cp -a "$UPSTREAM"/. "$FORK"/
chmod -R u+w "$FORK"

RESTORED=""
for f in $OURS; do
    if [ -e "$STAGE/$f" ]; then
        mkdir -p "$FORK/$(dirname "$f")"
        cp -a "$STAGE/$f" "$FORK/$f"
        RESTORED="$RESTORED $f"
    fi
done
echo "[rebase] restored our files:$RESTORED"

# Point the fork at our in-tree uTLS so it builds standalone (the main module's
# own replace is what governs the engine build).
(cd "$FORK" && "$GO" mod edit -replace=github.com/refraction-networking/utls=../utls)

# Re-apply our patches to the upstream files (new-files-only + patches).
if [ -d "$STAGE/patches" ]; then
    cp -a "$STAGE/patches" "$FORK/patches"
    for p in "$FORK"/patches/*.patch; do
        [ -e "$p" ] || continue
        echo "[rebase] applying $(basename "$p")"
        (cd "$FORK" && patch -p1 --forward < "$p")
    done
fi

echo "[rebase] tidying the vendored module"
(cd "$FORK" && "$GO" mod tidy)

echo "[rebase] rebuilding native engines"
(cd "$NATIVE" && "$GO" mod tidy)
(cd "$NATIVE" && CGO_ENABLED=1 "$GO" build -buildmode=c-shared -o libfreetls.so .)
(cd "$NATIVE" && CGO_ENABLED=1 "$GO" build -buildmode=c-shared -o libfreetls_go.so .)
echo "[rebase] done"
