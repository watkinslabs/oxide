#!/usr/bin/env bash
# libffi 3.4.6 static cross-build → vendor/libffi/install-<arch>/{lib,include}.
# Roadmap item 4: CPython _ctypes links libffi.a (static into the dynamic
# python binary, so no libffi.so runtime dep). Static archive only.
set -e
cd "$(dirname "$0")"
V=3.4.6
SRC="libffi-$V"
[ -d "$SRC" ] || { echo "run tools/fetch-libffi.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

build_one() {
  arch="$1"; triple="$2"; cc="$3"
  inst="install-$arch"
  echo "=== libffi $arch ($triple) ==="
  rm -rf "$inst" "$SRC/build-$arch"; mkdir -p "$SRC/build-$arch"
  abs="$(cd "$SRC" && pwd)/../$inst"
  # --disable-exec-static-tramp avoids tramp.c needing linux/limits.h (x86
  # musl-gcc lacks kernel UAPI). --includedir flattens ffi.h into include/.
  ( cd "$SRC/build-$arch" && \
    CC="$cc" sh ../configure --host="$triple" --build="$(sh ../config.guess)" \
      --prefix="$abs" --includedir="$abs/include" --libdir="$abs/lib" \
      --disable-shared --enable-static --disable-docs \
      --disable-exec-static-tramp >/dev/null \
    && make -j"$(nproc)" >/dev/null && make install >/dev/null )
  # libffi's configure forces lib64 on x86_64 multilib hosts regardless of
  # --libdir; normalise the static archive to a flat lib/ for both arches.
  if [ -f "$inst/lib64/libffi.a" ]; then
    mkdir -p "$inst/lib"; cp "$inst/lib64/libffi.a" "$inst/lib/libffi.a"; rm -rf "$inst/lib64"
  fi
  echo "  → $inst/lib/libffi.a ($(stat -c %s "$inst/lib/libffi.a") bytes); ffi.h: $(ls "$inst/include/ffi.h")"
}

build_one x86_64  x86_64-linux-musl  musl-gcc
build_one aarch64 aarch64-linux-musl "$CROSS/aarch64-linux-musl-gcc"
