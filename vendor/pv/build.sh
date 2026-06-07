#!/usr/bin/sh
# pv 1.8.5 build recipe — static-musl both arches. Drops in at /usr/bin/pv.
#
# pv (ivarch.com/programs/pv) is a non-TUI CLI progress meter for piped data.
# Plain autotools, no special deps: --disable-nls drops gettext, static link
# so it works pre-dynamic-linker. Exercises read/write/poll/select/ioctl
# (TIOCGWINSZ) on the rootfs path. `make distclean` between arches so the
# x86 object tree never leaks into the aarch64 build.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="pv-1.8.5"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-pv.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; host="$5"; strip_bin="$6"
  echo "=== building pv for $arch ==="
  cleanup_objs
  # GCC 15+ defaults to C23; pv's older sources trip K&R-style/old-cast
  # rejections, so -std=gnu89 + the -Wno-* keep the legacy behaviour
  # (same treatment rsync needed).
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -static -std=gnu89 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-error=incompatible-pointer-types $extra -D_GNU_SOURCE" \
    LDFLAGS="-static" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --disable-nls \
      --enable-static \
    && make -j4 \
  )
  if [ -f "$SRC/pv" ]; then
    cp "$SRC/pv" "pv-$suffix"
  else
    cp "$SRC/bin/pv" "pv-$suffix"
  fi
  "$strip_bin" "pv-$suffix" 2>/dev/null || strip "pv-$suffix" 2>/dev/null || true
  echo "  → pv-$suffix ($(stat -c %s "pv-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "$(uapi_cflags x86_64)" "x86_64"  "x86_64-linux-musl"  "strip"
build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" "aarch64" "aarch64-linux-musl" "$CROSS_ROOT/bin/aarch64-linux-musl-strip"

echo "OK — built pv for {x86_64, aarch64}"
