#!/usr/bin/sh
# util-linux 2.40.2 SHARED LIBS build (Track L2, mandatory systemd deps:
# libmount/libblkid/libuuid/libsmartcols). Separate from build.sh (which
# builds the static PROGRAMS) so this libs-only build with
# --disable-all-programs never touches the committed program blobs.
# Output: vendor/util-linux/install-<arch>/{lib/lib*.so*, include/...}.
set -e
cd "$(dirname "$0")"
SRC="util-linux-2.40.2"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-util-linux.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

build_one() {
  arch="$1"; cc="$2"; host="$3"; cflags="$4"
  install="install-${arch}"
  echo "=== building util-linux shared libs for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include/libmount" \
        "$install/include/blkid" "$install/include/uuid" "$install/include/libsmartcols"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && CC="$cc" CFLAGS="-Os $cflags -D_GNU_SOURCE" ./configure $host \
      --build=x86_64-pc-linux-gnu --disable-all-programs \
      --enable-libmount --enable-libblkid --enable-libuuid --enable-libsmartcols \
      --disable-static --enable-shared \
      --without-systemd --without-ncurses --without-ncursesw --without-tinfo \
      --without-readline --without-selinux --without-audit --disable-nls \
      --disable-rpath --disable-asciidoc >/dev/null && make -j4 >/dev/null )
  for so in libmount libblkid libuuid libsmartcols; do
    real=$(basename "$(readlink -f "$SRC/.libs/$so.so")")
    cp -L "$SRC/.libs/$real" "$install/lib/$real"
    soname=$(echo "$real" | sed 's/\(\.so\.[0-9]*\).*/\1/')
    ( cd "$install/lib" && ln -sf "$real" "$soname" && ln -sf "$soname" "$so.so" )
    echo "  → $install/lib/$real"
  done
  cp "$SRC/libmount/src/libmount.h"       "$install/include/libmount/" 2>/dev/null || true
  cp "$SRC/libblkid/src/blkid.h"          "$install/include/blkid/" 2>/dev/null || true
  cp "$SRC/libuuid/src/uuid.h"            "$install/include/uuid/" 2>/dev/null || true
  cp "$SRC/libsmartcols/src/libsmartcols.h" "$install/include/libsmartcols/" 2>/dev/null || true
}

build_one "x86_64"  "musl-gcc" "" "-idirafter /usr/include"
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl" ""
