#!/usr/bin/sh
# btop 1.4.0 build recipe — static-musl, C++20, for x86_64 + aarch64.
# Drops in at /usr/bin/btop.
#
# btop — resource monitor TUI. Pure C++20 (header-only fmt + ranges), no
# external lib deps beyond libstdc++/libgcc, which we link statically.
# Linux-only (collects from /proc, /sys); that suits oxide's Linux ABI.
#
# Toolchains: both arches use the musl.cc cross g++ (GCC 11.2.1) under
# vendor/cross/. The host `musl-gcc` is C-only (no g++), so even x86_64
# uses the cross toolchain here — that's the whole reason the x86_64 musl
# C++ cross toolchain was vendored. Run tools/fetch-cross.sh +
# tools/fetch-btop.sh first.
#
# Build knobs:
#   STATIC=true       -> Makefile adds -static -static-libgcc -static-libstdc++
#   ADDFLAGS=...      -> same, passed explicitly per the task contract
#   GPU_SUPPORT=false -> btop's GPU path dlopen()s libnvidia/librocm at
#                        runtime; in a fully-static binary dlopen is inert,
#                        and the build pulls extra in-tree Intel C sources.
#                        Disable it for a clean static link.
#   The Makefile already enforces -std=c++20 (REQFLAGS) and checks GCC>=10.1
#   (we ship 11.2.1).
set -e

cd "$(dirname "$0")"
SRC="btop-1.4.0"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-btop.sh first" >&2
  exit 1
fi

X86_ROOT="$(cd ../cross/x86_64-linux-musl-cross && pwd)"
X86_CXX="$X86_ROOT/bin/x86_64-linux-musl-g++"
X86_STRIP="$X86_ROOT/bin/x86_64-linux-musl-strip"

ARM_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
ARM_CXX="$ARM_ROOT/bin/aarch64-linux-musl-g++"
ARM_STRIP="$ARM_ROOT/bin/aarch64-linux-musl-strip"

for cxx in "$X86_CXX" "$ARM_CXX"; do
  [ -x "$cxx" ] || { echo "missing $cxx -- run tools/fetch-cross.sh first" >&2; exit 1; }
done

ADDFLAGS="-static -static-libstdc++ -static-libgcc"

build_one() {
  arch="$1"; cxx="$2"; strip="$3"
  echo "=== building btop for $arch ==="
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  ( cd "$SRC" && \
    make CXX="$cxx" STATIC=true GPU_SUPPORT=false \
         ADDFLAGS="$ADDFLAGS" -j4 )
  cp "$SRC/bin/btop" "btop-$arch"
  "$strip" "btop-$arch" 2>/dev/null || true
  echo "  -> btop-$arch ($(stat -c %s "btop-$arch") bytes)"
}

build_one "x86_64"  "$X86_CXX" "$X86_STRIP"
build_one "aarch64" "$ARM_CXX" "$ARM_STRIP"

( cd "$SRC" && make distclean >/dev/null 2>&1 || true )

echo "OK -- built btop for {x86_64, aarch64}"
