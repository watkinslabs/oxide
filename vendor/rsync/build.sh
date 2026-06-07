#!/usr/bin/sh
# rsync 3.3.0 build recipe — static-musl both arches. Drops in at
# /usr/bin/rsync.
#
# Self-contained: --with-included-popt + --with-included-zlib use rsync's
# bundled copies, so the link needs no external vendored libs. The optional
# compression/crypto extras (xxhash, zstd, lz4, openssl) are disabled
# because their libs aren't vendored; md2man (manpage gen via perl) is
# disabled too. roll-simd/roll-asm disabled so the cross-build pulls in no
# arch-specific intrinsics. Static link so it works pre-dynamic-linker.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="rsync-3.3.0"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-rsync.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

# rsync's configure runs a couple of guard tests it can't execute under a
# cross-compile (getpgrp arg count, fnmatch correctness). Pre-seed answers
# so the cross-build doesn't fall back to a "can't run test program" abort.
config_cache() {
  cat > config.cache <<'EOF'
ac_cv_func_getpgrp_void=yes
ac_cv_func_setpgrp_void=yes
rsync_cv_HAVE_BROKEN_LARGEFILE=no
rsync_cv_HAVE_C99_VSNPRINTF=yes
rsync_cv_have_working_fnmatch=yes
ac_cv_func_strcoll_works=yes
EOF
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; host="$5"; strip_bin="$6"
  echo "=== building rsync for $arch ==="
  cleanup_objs
  config_cache
  ( cd "$SRC" && \
    cp ../config.cache config.cache && \
    CC="$cc" \
    CFLAGS="-Os -static -std=gnu89 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-error=incompatible-pointer-types $extra -D_GNU_SOURCE" \
    LDFLAGS="-static" \
    ./configure \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --cache-file=config.cache \
      --prefix=/usr \
      --disable-md2man \
      --disable-xxhash \
      --disable-zstd \
      --disable-lz4 \
      --disable-openssl \
      --disable-roll-simd \
      --disable-roll-asm \
      --with-included-popt \
      --with-included-zlib \
    && make -j4 \
  )
  cp "$SRC/rsync" "rsync-$suffix"
  "$strip_bin" "rsync-$suffix" 2>/dev/null || strip "rsync-$suffix" 2>/dev/null || true
  rm -f config.cache
  echo "  → rsync-$suffix ($(stat -c %s "rsync-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "$(uapi_cflags x86_64)" "x86_64"  "x86_64-linux-musl"  "strip"
build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" "aarch64" "aarch64-linux-musl" "$CROSS_ROOT/bin/aarch64-linux-musl-strip"

echo "OK — built rsync for {x86_64, aarch64}"
