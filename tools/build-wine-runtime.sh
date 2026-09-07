#!/usr/bin/env bash
# tools/build-wine-runtime.sh — build the Windows runtime tree the guest runs.
#
# One pinned upstream Wine release, one patch set, one output tree. The image
# never copies a Windows module from the build host: this script produces
# `target/artifacts/wine/<arch>` and `oxide-wine` packages exactly that tree
# (`packages/manifests/packages.toml`), the way `oxide-kernel` packages the
# kernel artifacts.
#
# Inputs (fetched by tools/fetch-vendor.sh, never taken from an installed
# host Wine):
#   vendor/wine/wine-<version>.tar.xz            upstream release tarball
#   vendor/wine/mingw64-headers-<hdr>.noarch.rpm mingw-w64 CRT headers for the PE side
#   tools/wine-patches/*.patch                   Oxide-owned source changes
#
# Output layout, mirroring the Wine install layout the runtime configuration
# names:
#   <out>/x86_64-windows/*.dll,*.exe   PE modules (the guest's Windows side)
#   <out>/x86_64-unix/*.so             Unixlibs (ntdll.so / win32u.so included)
#   <out>/nls/*.nls                    NLS catalog
#   <out>/wine-version                 the single version stamp staging verifies

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# One pin for the whole tree: the packaging, the fetch and the image-side
# version gate all read tools/wine-version.
WINE_VERSION="$(tr -d "[:space:]" < "$REPO_ROOT/tools/wine-version")"
MINGW_HEADERS_RPM="${OXIDE_MINGW_HEADERS_RPM:-$REPO_ROOT/vendor/wine/mingw64-headers-12.0.0-4.fc42.noarch.rpm}"
TARBALL="${OXIDE_WINE_TARBALL:-$REPO_ROOT/vendor/wine/wine-$WINE_VERSION.tar.xz}"
PATCH_DIR="${OXIDE_WINE_PATCH_DIR:-$REPO_ROOT/tools/wine-patches}"
WORK="${OXIDE_WINE_WORK:-$REPO_ROOT/target/wine}"
OUT="${OXIDE_WINE_OUT:-$REPO_ROOT/target/artifacts/wine/x86_64}"
JOBS="${OXIDE_WINE_JOBS:-$(nproc)}"

die() { echo "build-wine-runtime: $*" >&2; exit 1; }

[ -f "$TARBALL" ] || die "missing $TARBALL — run tools/fetch-vendor.sh"
[ -f "$MINGW_HEADERS_RPM" ] || die "missing $MINGW_HEADERS_RPM — run tools/fetch-vendor.sh"
command -v clang >/dev/null || die "clang is the PE cross compiler; install it"

SRC="$WORK/wine-$WINE_VERSION"
BUILD="$WORK/build-$WINE_VERSION"
HEADERS="$WORK/mingw64-headers"

mkdir -p "$WORK"

if [ ! -f "$SRC/.oxide-prepared" ]; then
    rm -rf "$SRC"
    mkdir -p "$SRC"
    tar -xf "$TARBALL" -C "$WORK"
    [ -f "$SRC/VERSION" ] || die "tarball did not unpack to $SRC"
    grep -q "Wine version $WINE_VERSION" "$SRC/VERSION" || die "$SRC/VERSION is not Wine $WINE_VERSION"
    for patch in "$PATCH_DIR"/*.patch; do
        [ -e "$patch" ] || break
        echo "build-wine-runtime: applying $(basename "$patch")"
        ( cd "$SRC" && patch -p1 --fuzz=5 --no-backup-if-mismatch < "$patch" ) || die "patch $(basename "$patch") did not apply"
    done
    touch "$SRC/.oxide-prepared"
fi

if [ ! -d "$HEADERS/usr" ]; then
    rm -rf "$HEADERS"; mkdir -p "$HEADERS"
    ( cd "$HEADERS" && rpm2cpio "$MINGW_HEADERS_RPM" | cpio -idm --quiet )
fi
INCLUDE="$HEADERS/usr/x86_64-w64-mingw32/sys-root/mingw/include"
[ -d "$INCLUDE" ] || die "mingw headers did not unpack to $INCLUDE"

if [ ! -f "$BUILD/Makefile" ]; then
    mkdir -p "$BUILD"
    ( cd "$BUILD" && x86_64_CFLAGS="-isystem $INCLUDE" x86_64_CXXFLAGS="-isystem $INCLUDE" \
        "$SRC/configure" --enable-win64 --with-mingw=clang --disable-tests --disable-win16 CC=gcc )
fi

make -C "$BUILD" -j"$JOBS"

DESTDIR="$WORK/dest-$WINE_VERSION"
rm -rf "$DESTDIR"
make -C "$BUILD" -j"$JOBS" install DESTDIR="$DESTDIR" >/dev/null

# The install prefix is Wine's own; the guest tree is ours. Take exactly the
# three catalogs the runtime configuration names, so nothing else the install
# produced (loader, tools, man pages) can reach the image.
PREFIX="$DESTDIR/usr/local"
rm -rf "$OUT"
mkdir -p "$OUT/x86_64-windows" "$OUT/x86_64-unix" "$OUT/nls"
cp -a "$PREFIX/lib/wine/x86_64-windows/." "$OUT/x86_64-windows/"
cp -a "$PREFIX/lib/wine/x86_64-unix/." "$OUT/x86_64-unix/"
cp -a "$PREFIX/share/wine/nls/." "$OUT/nls/"
printf '%s\n' "$WINE_VERSION" > "$OUT/wine-version"

modules=$(find "$OUT/x86_64-windows" -maxdepth 1 -type f \( -name '*.dll' -o -name '*.exe' \) | wc -l)
unixlibs=$(find "$OUT/x86_64-unix" -maxdepth 1 -type f -name '*.so' | wc -l)
[ "$modules" -gt 0 ] || die "no PE modules installed"
[ "$unixlibs" -gt 0 ] || die "no unixlibs installed"
[ -f "$OUT/x86_64-windows/notepad.exe" ] || die "notepad.exe absent from the PE catalog"
[ -f "$OUT/x86_64-unix/ntdll.so" ] || die "ntdll.so absent from the unixlib catalog"
# The runtime tree is the complete upstream build, and the image stages all of
# it: the NT runtime module is what the kernel hands each process over to, and
# the audit gate reads the same image out of this tree.
[ -f "$OUT/x86_64-windows/ntdll.dll" ] || die "ntdll.dll absent from the PE catalog"
[ -f "$OUT/x86_64-unix/win32u.so" ] || die "win32u.so absent from the unixlib catalog"
grep -q wine_oxide_attach_thread <(nm -D --defined-only "$OUT/x86_64-unix/ntdll.so") \
    || die "ntdll.so does not export the Oxide attach entry — the patch set did not reach the build"
echo "build-wine-runtime: wine=$WINE_VERSION modules=$modules unixlibs=$unixlibs out=$OUT"
