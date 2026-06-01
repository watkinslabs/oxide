#!/usr/bin/sh
# attr 2.5.2 SHARED build — per-arch libattr.so under
# vendor/attr/install-<arch>/{lib,include}.
# Track L2: acl's dep; systemd journal/udev xattr handling.
set -e
cd "$(dirname "$0")"
SRC="attr-2.5.2"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-attr.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
COMMON="--enable-shared --disable-static --disable-nls --disable-rpath"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libattr.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include/attr"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  extra=""
  [ "$arch" = "x86_64" ] && extra="-idirafter /usr/include"
  # Non-recursive automake: build just the library target. The
  # `attr`/`getfattr` CLI tools use GNU basename() which musl lacks, and
  # we ship only libattr.so.
  ( cd "$SRC" && CC="$cc" CFLAGS="-O2 -fPIC $extra" ./configure $host $COMMON >/dev/null \
      && make -j4 libmisc.la libattr.la >/dev/null )
  real="$(cd "$SRC/.libs" && ls libattr.so.1.* 2>/dev/null | grep -v '\.la$' | head -1)"
  [ -n "$real" ] || { echo "no libattr.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libattr.so.1 && ln -sf libattr.so.1 libattr.so )
  cp "$SRC"/include/*.h "$install/include/attr/" 2>/dev/null || true
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"
