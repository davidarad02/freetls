#!/bin/sh
# Update the vendored OpenSSL submodule to <tag> (shallow) and rebuild the wide
# engine. Transparent: prints the old -> new version and refreshes the gitlink.
#
# Usage:
#   tools/update_openssl.sh openssl-3.5.6
#   make update-openssl TAG=openssl-3.5.6
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
OPENSSL_DIR="$ROOT/native/third_party/openssl"

TAG="${1:-}"
if [ -z "$TAG" ]; then
    echo "usage: tools/update_openssl.sh <tag>   e.g. openssl-3.5.6" >&2
    exit 1
fi

if [ ! -e "$OPENSSL_DIR/.git" ]; then
    echo "OpenSSL submodule not initialized. Run:" >&2
    echo "  git submodule update --init --depth 1 native/third_party/openssl" >&2
    exit 1
fi

old=$(git -C "$OPENSSL_DIR" describe --tags --always 2>/dev/null || git -C "$OPENSSL_DIR" rev-parse --short HEAD)
echo "[update-openssl] current: $old"
echo "[update-openssl] fetching $TAG (shallow)..."
git -C "$OPENSSL_DIR" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"
git -C "$OPENSSL_DIR" checkout --detach "$TAG"
new=$(git -C "$OPENSSL_DIR" describe --tags --always 2>/dev/null || git -C "$OPENSSL_DIR" rev-parse --short HEAD)
echo "[update-openssl] new: $new"

# Record the new commit in the parent repository's gitlink.
git -C "$ROOT" add "$OPENSSL_DIR"

# Force a rebuild of libcrypto.a (drop the stamp) and rebuild the wide engine.
rm -f "$OPENSSL_DIR/libcrypto.a" "$OPENSSL_DIR/.freetls-built"
make -C "$ROOT" native

echo "[update-openssl] done: $old -> $new"
echo "[update-openssl] commit the updated submodule pointer + rebuilt artifacts as needed."
