#!/usr/bin/sh
# libgcrypt 1.10.3 SHARED build — per-arch libgcrypt.so under
# vendor/libgcrypt/install-<arch>/{lib,include}.
# Track L2: systemd unconditional DEPENDS (journald FSS sealing).
# Depends on libgpg-error: libgcrypt's configure needs its gpgrt-config,
# so we install libgpg-error into a per-arch prefix here and point
# --with-libgpg-error-prefix at it (build-host only; the staged runtime
# dep is the libgpg-error.so already in /usr/lib via F341).
set -e
cd "$(dirname "$0")"
SRC="libgcrypt-1.10.3"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-libgcrypt.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
GPGE_SRC="$(cd ../libgpg-error/libgpg-error-1.50 2>/dev/null && pwd || true)"
[ -n "$GPGE_SRC" ] || { echo "missing libgpg-error source — run tools/fetch-libgpg-error.sh" >&2; exit 1; }

# libgcrypt can't run target binaries when cross; pre-seed its hw-feature
# + sizeof probes.
CACHE="ac_cv_sys_symbol_underscore=no"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  gpge_prefix="$(pwd)/gpge-prefix-${arch}"
  echo "=== building libgcrypt.so for $arch ==="
  rm -rf "$install" "$gpge_prefix"; mkdir -p "$install/lib" "$install/include"
  extra=""
  [ "$arch" = "x86_64" ] && extra="-idirafter /usr/include"

  # 1. install libgpg-error into a private prefix for its gpgrt-config.
  ( cd "$GPGE_SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$GPGE_SRC" && CC="$cc" CFLAGS="-O2 -fPIC $extra" \
      ./configure $host --prefix="$gpge_prefix" \
      --enable-shared --disable-static --disable-doc --disable-tests \
      --disable-languages --disable-nls >/dev/null && make -j4 >/dev/null && make install >/dev/null )

  # 2. libgcrypt against that prefix. libgcrypt's configure searches
  # only its OWN --prefix/bin + PATH for gpgrt-config (it ignores
  # --with-libgpg-error-prefix for that), so hand it the absolute
  # GPGRT_CONFIG path (the m4 honors a /-prefixed override) and put it
  # on PATH.
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  # arm cross-ld is strict: when it links the bundled test programs
  # against libgcrypt.so it re-checks libgcrypt.so's own undefined
  # symbols and needs to find libgpg-error.so to resolve the transitive
  # DT_NEEDED. -rpath-link points it at the gpg-error libdir without
  # adding libgpg-error to each test's DT_NEEDED.
  ( cd "$SRC" && env $CACHE CC="$cc" CFLAGS="-O2 -fPIC $extra" \
      LDFLAGS="-Wl,-rpath-link,$gpge_prefix/lib" \
      GPGRT_CONFIG="$gpge_prefix/bin/gpgrt-config" \
      PATH="$gpge_prefix/bin:$PATH" \
      ./configure $host \
      --enable-shared --disable-static --disable-doc --disable-tests \
      --with-libgpg-error-prefix="$gpge_prefix" \
      --disable-asm >/dev/null && make -j4 >/dev/null )
  real="$(cd "$SRC/src/.libs" && ls libgcrypt.so.20.* 2>/dev/null | head -1)"
  [ -n "$real" ] || { echo "no libgcrypt.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/src/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libgcrypt.so.20 && ln -sf libgcrypt.so.20 libgcrypt.so )
  cp "$SRC/src/gcrypt.h" "$install/include/"
  # gcrypt.h #includes <gpg-error.h>; stage it alongside so a probe's
  # single `-I include` resolves both.
  cp "$gpge_prefix/include/gpg-error.h" "$install/include/" 2>/dev/null \
    || cp "../libgpg-error/install-${arch}/include/gpg-error.h" "$install/include/"
  rm -rf "$gpge_prefix"
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"
