#!/usr/bin/sh
# openssl 3.0.15 SHARED build — per-arch libssl.so.3 + libcrypto.so.3
# under vendor/openssl/install-<arch>/{lib,include}.
# Track L2: systemd resolved DoT/DNSSEC + journal TLS (openssl >= 3.0).
# `make build_libs` builds just the two libs (no apps/tests).
set -e
cd "$(dirname "$0")"
SRC="openssl-3.0.15"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-openssl.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

build_one() {
  arch="$1"; target="$2"; crosspfx="$3"
  install="install-${arch}"
  echo "=== building openssl libs for $arch ($target) ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  extra=""
  [ "$arch" = "x86_64" ] && extra="-idirafter /usr/include"
  # x86 uses musl-gcc directly; arm sets --cross-compile-prefix (full
  # path) so Configure picks the cross gcc/ar/ranlib. no-tests/no-docs/
  # no-module/no-legacy minimise; `make build_libs` skips apps. shared on.
  if [ "$arch" = "x86_64" ]; then ccenv="CC=musl-gcc"; else ccenv=""; fi
  ( cd "$SRC" && env $ccenv ./Configure "$target" $crosspfx shared no-tests \
      no-module no-legacy --release CFLAGS="-O2 $extra" >/dev/null \
      && make -j4 build_libs >/dev/null )
  for l in libssl libcrypto; do
    cp -L "$SRC/$l.so.3" "$install/lib/$l.so.3"
    ( cd "$install/lib" && ln -sf "$l.so.3" "$l.so" )
  done
  cp -r "$SRC/include/openssl" "$install/include/openssl"
  echo "  → $install/lib/libssl.so.3 ($(stat -c %s "$install/lib/libssl.so.3") bytes) + libcrypto.so.3"
}

build_one "x86_64"  "linux-x86_64"  ""
build_one "aarch64" "linux-aarch64" "--cross-compile-prefix=${CROSS}/aarch64-linux-musl-"
