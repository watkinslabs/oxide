#!/usr/bin/sh
# dbus 1.14.10 SHARED build — per-arch libdbus-1.so under
# vendor/dbus/install-<arch>/{lib/libdbus-1.so*, include/...}.
# Track L2: mandatory systemd bus stack (libdbus-1). Autotools.
# XML backend = our cross-built expat (vendor/expat/install-<arch>).
# We only need the shared lib; the daemon is built but not staged.
set -e
cd "$(dirname "$0")"
SRC="dbus-1.14.10"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-dbus.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
EXPAT_ROOT="$(cd ../expat && pwd)"

# dbus configure runs link/exec probes that a cross build can't execute;
# pre-seed the cache with the Linux/musl answers so --host doesn't choke.
CACHE="ac_cv_have_abstract_sockets=yes \
ac_cv_func_posix_getpwnam_r=yes \
ac_cv_lib_expat_XML_ParserCreate_MM=yes \
ac_cv_func_writev=yes \
ac_cv_func_socketpair=yes"

COMMON="--enable-shared --disable-static --disable-tests --disable-asserts \
--disable-doxygen-docs --disable-xml-docs --disable-ducktype-docs \
--without-x --disable-selinux --disable-apparmor --disable-systemd \
--disable-launchd --with-xml=expat"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  expat_inc="${EXPAT_ROOT}/install-${arch}/include"
  expat_lib="${EXPAT_ROOT}/install-${arch}/lib"
  [ -f "${expat_lib}/libexpat.so.1" ] || { echo "missing expat for $arch — run vendor/expat/build.sh first" >&2; exit 1; }
  echo "=== building libdbus-1.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  # x86 kernel UAPI headers (musl-gcc lacks some linux/*); arm cross
  # sysroot already bundles them.
  extra_cflags=""
  [ "$arch" = "x86_64" ] && extra_cflags="-idirafter /usr/include"
  ( cd "$SRC" && env $CACHE \
      CC="$cc" \
      CFLAGS="-O2 -fPIC $extra_cflags -I${expat_inc}" \
      LDFLAGS="-L${expat_lib}" \
      EXPAT_CFLAGS="-I${expat_inc}" EXPAT_LIBS="-L${expat_lib} -lexpat" \
      ./configure $host $COMMON >/dev/null && make -j4 >/dev/null )
  real="$(cd "$SRC/dbus/.libs" && ls libdbus-1.so.3.*.* 2>/dev/null | head -1)"
  [ -n "$real" ] || { echo "no libdbus-1.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/dbus/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libdbus-1.so.3 && ln -sf libdbus-1.so.3 libdbus-1.so )
  # Public headers flat under include/dbus/ so a probe's `-I include`
  # resolves both <dbus/dbus.h> and its internal <dbus/dbus-arch-deps.h>
  # (dbus-arch-deps.h is configure-generated, per-arch).
  mkdir -p "$install/include/dbus"
  cp "$SRC"/dbus/dbus*.h "$install/include/dbus/" 2>/dev/null || true
  cp "$SRC"/dbus/dbus-arch-deps.h "$install/include/dbus/" 2>/dev/null || true
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"
