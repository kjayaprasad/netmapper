#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(awk -F '"' '$1 ~ /^version = / { print $2; exit }' "$ROOT/Cargo.toml")
DEB_VERSION="${VERSION}.0"
PACKAGE_NAME="netmapperv2"
ARCH=$(dpkg --print-architecture)
STAGING=$(mktemp -d)
OUTPUT_DIR="$ROOT/dist"
OUTPUT="$OUTPUT_DIR/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"
LEGACY_OUTPUT="$OUTPUT_DIR/netmapper.dpkg"
PARENT_OUTPUT="$ROOT/../${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"
PARENT_LEGACY_OUTPUT="$ROOT/../netmapper.dpkg"
BINARY="$ROOT/target/release/netmapper"

if [ -z "$VERSION" ]; then
    echo "Could not read package version from Cargo.toml" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1 || ! command -v dpkg-deb >/dev/null 2>&1 || ! command -v objdump >/dev/null 2>&1; then
    echo "Building requires cargo, dpkg-deb, and objdump (binutils)" >&2
    exit 1
fi

cleanup() {
    rm -rf "$STAGING"
}
trap cleanup EXIT HUP INT TERM

cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked
GLIBC_VERSION=$(objdump -T "$BINARY" | sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -Vu | tail -n 1)
if [ -z "$GLIBC_VERSION" ]; then
    echo "Could not determine the binary's minimum GLIBC version" >&2
    exit 1
fi
mkdir -p "$STAGING/DEBIAN" "$STAGING/usr/bin" "$STAGING/usr/share/man/man1" \
    "$STAGING/usr/share/icons/hicolor/scalable/apps" "$OUTPUT_DIR"
install -m 0755 "$BINARY" "$STAGING/usr/bin/netmapper"
install -m 0644 "$ROOT/man/netmapper.1" "$STAGING/usr/share/man/man1/netmapper.1"
install -m 0644 "$ROOT/assets/netmapper.svg" \
    "$STAGING/usr/share/icons/hicolor/scalable/apps/netmapper.svg"
sed -e "s/@VERSION@/$DEB_VERSION/g" -e "s/@ARCH@/$ARCH/g" \
    "$ROOT/debian/control.in" > "$STAGING/DEBIAN/control"
sed -i "s/@GLIBC_VERSION@/$GLIBC_VERSION/g" "$STAGING/DEBIAN/control"
printf '\n' >> "$STAGING/DEBIAN/control"
dpkg-deb --root-owner-group --build "$STAGING" "$OUTPUT"
install -m 0644 "$OUTPUT" "$LEGACY_OUTPUT"
install -m 0644 "$OUTPUT" "$PARENT_OUTPUT"
install -m 0644 "$OUTPUT" "$PARENT_LEGACY_OUTPUT"
printf 'Created %s\n' "$OUTPUT"
printf 'Created compatibility copy %s\n' "$LEGACY_OUTPUT"
printf 'Copied versioned package to %s\n' "$PARENT_OUTPUT"
printf 'Copied compatibility package to %s\n' "$PARENT_LEGACY_OUTPUT"