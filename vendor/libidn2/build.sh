#!/usr/bin/sh
# libidn2 2.3.7 SHARED build — per-arch libidn2.so under
# vendor/libidn2/install-<arch>/{lib,include}.
# Track L2: systemd-resolved IDNA (libidn2). DT_NEEDEDs libunistring (F346).
set -e
cd "$(dirname "$0")"
SRC="libidn2-2.3.7"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-libidn2.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
UNI_ROOT="$(cd ../libunistring && pwd)"
COMMON="--enable-shared --disable-static --disable-doc --disable-nls --disable-rpath"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  uni="${UNI_ROOT}/install-${arch}"
  [ -f "${uni}/lib/libunistring.so" ] || { echo "missing libunistring for $arch — run vendor/libunistring/build.sh first" >&2; exit 1; }
  echo "=== building libidn2.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  # gendata/gentr46map are cross-compiled (arm) and can't run on the host;
  # but their output (data.c, tr46map_data.c) is arch-independent Unicode
  # data. Restore the copies saved from the x86 build so the arm build
  # skips regenerating them.
  if [ "$arch" = "aarch64" ] && [ -f /tmp/oxide-idn2-data.c ]; then
    cp /tmp/oxide-idn2-data.c "$SRC/lib/data.c"
    cp /tmp/oxide-idn2-tr46map_data.c "$SRC/lib/tr46map_data.c"
  fi
  # NB: no `-idirafter /usr/include` — libidn2 needs no kernel UAPI, and
  # leaking host glibc headers breaks its bundled gnulib on musl (gnulib
  # dup2.c → implicit-declaration errors).
  extra=""
  # arm cross-ld: -rpath-link so libidn2.so's transitive libunistring.so
  # resolves when linking the bundled tools.
  # gnulib's runtime feature tests default pessimistic and build broken
  # replacements for musl's perfectly-good dup2/fcntl (gl_cv_..._works=no
  # → rpl_* that fail to declare the real symbol). Pre-seed the cache so
  # gnulib uses musl's functions directly.
  GLCACHE="gl_cv_func_dup2_works=yes gl_cv_func_fcntl_f_dupfd_works=yes \
gl_cv_func_fcntl_f_dupfd_cloexec=yes gl_cv_func_open_directory_works=yes"
  # Do NOT add -I${uni}/include: it drags libunistring's gnulib
  # replacement headers (stdbool.h etc.) onto the global path → infinite
  # include recursion in libidn2's own bundled gnulib. --with-libunistring-
  # prefix locates the lib's public API correctly without that.
  # gendata/gentr46map are build-time codegen tools run on the HOST;
  # build them with host gcc (CC_FOR_BUILD) so the arm cross-build doesn't
  # produce arm binaries that can't exec (cf. libcap _makenames).
  ( cd "$SRC" && env $GLCACHE CC="$cc" CC_FOR_BUILD=gcc BUILD_CC=gcc \
      CFLAGS="-O2 -fPIC -D_GNU_SOURCE $extra" \
      LDFLAGS="-L${uni}/lib -Wl,-rpath-link,${uni}/lib" \
      ./configure $host $COMMON --with-libunistring-prefix="${uni}" >/dev/null )
  # After configure, ensure the restored generated files look up-to-date
  # so make doesn't run the (cross-built, unrunnable) gen tools.
  if [ "$arch" = "aarch64" ] && [ -f "$SRC/lib/data.c" ]; then
    touch "$SRC/lib/data.c" "$SRC/lib/tr46map_data.c"
  fi
  ( cd "$SRC" && make -j4 >/dev/null )
  # Save the arch-independent generated data from the x86 build for arm.
  if [ "$arch" = "x86_64" ]; then
    cp "$SRC/lib/data.c" /tmp/oxide-idn2-data.c
    cp "$SRC/lib/tr46map_data.c" /tmp/oxide-idn2-tr46map_data.c
  fi
  real="$(cd "$SRC/lib/.libs" && ls libidn2.so.0.* 2>/dev/null | head -1)"
  [ -n "$real" ] || { echo "no libidn2.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/lib/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libidn2.so.0 && ln -sf libidn2.so.0 libidn2.so )
  cp "$SRC/lib/idn2.h" "$install/include/" 2>/dev/null || true
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"
