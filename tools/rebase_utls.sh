#!/bin/sh
# Re-copy the pinned upstream uTLS into native/third_party/utls, restore our
# added files, and rebuild the engine.
#
# Usage: tools/rebase_utls.sh [version]
#   version defaults to the one pinned in native/go.mod.
#
# Our added files (new files only; upstream files are never edited) are listed
# in OURS below and are preserved across the rebase.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
NATIVE="$ROOT/native"
FORK="$NATIVE/third_party/utls"

# Files that are ours (not from upstream) and must survive a rebase.
OURS="FORK.md freetls_buildtag.go freetls_buildtag_libcrypto.go \
freetls_supported.go cipher_evp_register.go aead_evp.go block_evp.go \
evp_cgo.go evp_freetls_test.go \
ffdhe_key_agreement.go ffdhe_dsa.go ffdhe_ciphers.go ffdhe_ciphers_evp.go \
ffdhe_freetls_test.go"

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
    VER=$(sed -n 's/.*github.com\/refraction-networking\/utls \(v[^ ]*\).*/\1/p' "$NATIVE/go.mod" | head -1)
fi
[ -n "$VER" ] || { echo "could not determine pinned uTLS version" >&2; exit 1; }
echo "[rebase] pinned uTLS version: $VER"

GOMODCACHE=$(cd "$NATIVE" && "$GO" env GOMODCACHE)
UPSTREAM="$GOMODCACHE/github.com/refraction-networking/utls@$VER"
if [ ! -d "$UPSTREAM" ]; then
    echo "[rebase] downloading $VER into the module cache"
    (cd "$NATIVE" && "$GO" mod download "github.com/refraction-networking/utls@$VER")
fi
[ -d "$UPSTREAM" ] || { echo "upstream module not found at $UPSTREAM" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
for f in $OURS; do
    if [ -e "$FORK/$f" ]; then cp -a "$FORK/$f" "$STAGE/$f"; fi
done

mkdir -p "$FORK"
find "$FORK" -mindepth 1 -delete
cp -a "$UPSTREAM"/. "$FORK"/
chmod -R u+w "$FORK"

RESTORED=""
for f in $OURS; do
    if [ -e "$STAGE/$f" ]; then
        cp -a "$STAGE/$f" "$FORK/$f"
        RESTORED="$RESTORED $f"
    fi
done
echo "[rebase] restored our files:$RESTORED"

echo "[rebase] rebuilding native engine"
(cd "$NATIVE" && CGO_ENABLED=1 "$GO" build -buildmode=c-shared -o libfreetls.so .)
echo "[rebase] done"
