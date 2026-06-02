#!/usr/bin/env bash
# Cross-build static-musl CPython 3.13.1 for x86_64 + aarch64.
# Roadmap item 4. Outputs vendor/python/python3-{x86_64,aarch64}.
# CPython cross-compile needs a host python of the same X.Y first
# (--with-build-python). _ctypes (libffi) disabled — not vendored.
set -e
cd "$(dirname "$0")"
V=3.13.1
SRC="Python-$V"
ROOT="$(cd ../.. && pwd)"
JOBS="$(nproc)"
[ -d "$SRC" ] || { echo "run tools/fetch-python.sh first" >&2; exit 1; }

# 1. host python (build-python for the cross steps)
HOSTBUILD="$SRC/build-host"
if [ ! -x "$HOSTBUILD/python" ]; then
  rm -rf "$HOSTBUILD"; mkdir -p "$HOSTBUILD"
  ( cd "$HOSTBUILD" && ../configure -q && make -s -j"$JOBS" python )
fi
HOSTPY="$(cd "$HOSTBUILD" && pwd)/python"
echo "host python: $($HOSTPY --version)"

build_one() {
  arch="$1"; cc="$2"; triple="$3"
  echo "=== cross python $arch ==="
  ZL="$ROOT/vendor/zlib/install-$arch"
  SSL="$ROOT/vendor/openssl/install-$arch"
  bd="$SRC/build-$arch"
  rm -rf "$bd"; mkdir -p "$bd"
  ( cd "$bd" && \
    CC="$cc" \
    ../configure \
      --host="$triple" --build="$(../config.guess)" \
      --with-build-python="$HOSTPY" \
      --disable-shared --without-ensurepip --disable-test-modules \
      --with-ensurepip=no \
      ac_cv_file__dev_ptmx=no ac_cv_file__dev_ptc=no \
      ac_cv_buggy_getaddrinfo=no \
      CFLAGS="-I$ZL/include -I$SSL/include" \
      CPPFLAGS="-I$ZL/include -I$SSL/include" \
      LDFLAGS="-static -L$ZL/lib -L$SSL/lib" \
    && make -s -j"$JOBS" python )
  cp "$bd/python" "python3-$arch"
  echo "BUILT python3-$arch:"; file "python3-$arch"
}

build_one x86_64 "musl-gcc" "x86_64-linux-musl"
build_one aarch64 "$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc" "aarch64-linux-musl"
