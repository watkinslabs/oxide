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

# Fully-static interpreter: every detected stdlib C extension must be
# builtin (a -static link can't produce loadable .so). Copy configure's
# Setup.stdlib with *shared*->*static*, and disable modules whose libs
# aren't vendored (bz2/lzma/ctypes/curses/readline/ssl/...). _ssl/_hashlib
# stay off until openssl cross-detection lands; hashlib md5/sha still work
# via the builtin _md5/_sha* modules.
# Run with cwd == build dir (inside the configure/make subshell).
write_setup_local() {
  { printf '*disabled*\n_bz2\n_lzma\n_ctypes\n_ctypes_test\n_curses\n'
    printf '_curses_panel\nreadline\nnis\n_dbm\n_gdbm\n_tkinter\n_ssl\n'
    printf '_hashlib\nossaudiodev\nspwd\n_testcapi\n_testbuffer\n'
    printf '_testimportmultiple\nxxlimited\nxxlimited_35\n\n'
    sed 's/^\*shared\*/*static*/' Modules/Setup.stdlib
  } > Modules/Setup.local
}

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
    && write_setup_local \
    && make -s -j"$JOBS" )
  cp "$bd/python" "python3-$arch"
  "${cc%gcc}strip" "python3-$arch" 2>/dev/null || strip "python3-$arch" || true
  echo "BUILT python3-$arch:"; file "python3-$arch"
}

build_one x86_64 "musl-gcc" "x86_64-linux-musl"
build_one aarch64 "$ROOT/vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc" "aarch64-linux-musl"

# Arch-independent stdlib zip (zipimport, DEFLATE — zlib is builtin).
# Trim test/idle/tkinter/lib2to3/ensurepip/site-packages: a runtime
# stdlib, not a dev tree. Staged at /usr/lib/python313.zip; CPython's
# getpath adds <prefix>/lib/python313.zip to sys.path automatically.
echo "=== stdlib zip ==="
( cd "$SRC/Lib" && rm -f "$ROOT/vendor/python/python313.zip" && \
  zip -q -r -X "$ROOT/vendor/python/python313.zip" . \
    -x 'test/*' '*/test/*' 'tests/*' '*/tests/*' 'idlelib/*' 'tkinter/*' \
       'lib2to3/*' 'ensurepip/*' '__pycache__/*' '*/__pycache__/*' \
       'site-packages/*' 'turtledemo/*' 'config-*/*' )
ls -la "$ROOT/vendor/python/python313.zip"
