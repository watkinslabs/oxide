#!/usr/bin/sh
# pcre2 10.44 SHARED build — per-arch libpcre2-8.so under
# vendor/pcre2/install-<arch>/{lib/libpcre2-8.so*, include/pcre2.h}.
# Track L2 systemd dep (journal field pattern matching). Autotools.
set -e
cd "$(dirname "$0")"
SRC="pcre2-10.44"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-pcre2.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
COMMON="--enable-shared --disable-static --disable-pcre2grep-jit"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  echo "=== building libpcre2-8.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && ./configure CC="$cc" $host $COMMON >/dev/null && make -j4 >/dev/null )
  cp -L "$SRC/.libs/libpcre2-8.so.0.13.0" "$install/lib/libpcre2-8.so.0.13.0"
  ( cd "$install/lib" && ln -sf libpcre2-8.so.0.13.0 libpcre2-8.so.0 && ln -sf libpcre2-8.so.0 libpcre2-8.so )
  cp "$SRC/src/pcre2.h" "$install/include/"
  echo "  → $install/lib/libpcre2-8.so.0.13.0 ($(stat -c %s "$install/lib/libpcre2-8.so.0.13.0") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"
