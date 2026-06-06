#!/usr/bin/sh
# procps-ng 4.0.5 build recipe -- D3 of distro roadmap.
# Static-musl. ps, top, free, vmstat, uptime, pgrep, pkill, pmap,
# tload, w, watch, slabtop, sysctl.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="procps-ng-4.0.5"
if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-procps-ng.sh first" >&2
  exit 1
fi

# Bootstrap autotools the first time (autogen runs autoconf/automake/etc.).
( cd "$SRC" && [ -f configure ] || ./autogen.sh )

HDRS_X86=/tmp/musl-hdrs-procps
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-procps-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_AR="$CROSS_ROOT/bin/aarch64-linux-musl-ar"
CROSS_RANLIB="$CROSS_ROOT/bin/aarch64-linux-musl-ranlib"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

# Programs to ship.
PROGRAMS="ps/pscommand top/top free vmstat uptime pgrep pmap tload w watch slabtop sysctl"

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"; nc_root="$5"; host="$6"; ar="$7"; ranlib="$8"
  echo "=== building procps for $arch ==="
  cleanup_objs
  cat > "$SRC/config.cache" <<EOF
ac_cv_func_malloc_0_nonnull=yes
ac_cv_func_realloc_0_nonnull=yes
EOF
  ( cd "$SRC" && \
    CC="$cc" \
    AR="$ar" \
    RANLIB="$ranlib" \
    CFLAGS="-Os -static $extra -D_GNU_SOURCE -I${nc_root}/include -I${nc_root}/include/ncursesw -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS="-static -L${nc_root}/lib" \
    LIBS="-lncursesw" \
    NCURSES_LIBS="-L${nc_root}/lib -lncursesw" \
    NCURSES_CFLAGS="-I${nc_root}/include -I${nc_root}/include/ncursesw" \
    ./configure --cache-file=config.cache \
      --host="$host" \
      --build="x86_64-pc-linux-gnu" \
      --prefix=/usr \
      --bindir=/bin --sbindir=/sbin \
      --disable-nls \
      --disable-rpath \
      --disable-shared \
      --enable-static \
      --without-systemd \
      --without-elogind \
      --disable-modern-top \
    && make -j4 \
  )
  # Programs end up under different subdirs; locate each by name.
  for pname in top free vmstat uptime pgrep pkill pmap tload w watch slabtop sysctl; do
    found=$(find $SRC -maxdepth 4 -type f -name "$pname" -executable ! -name "*.sh" 2>/dev/null | head -1)
    [ -n "$found" ] || continue
    cp "$found" "$pname-$suffix"
    strip "$pname-$suffix" 2>/dev/null || true
    echo "  -> $pname-$suffix ($(stat -c %s $pname-$suffix) bytes)"
  done
  # ps installs as 'pscommand' inside src/ps/ — copy + rename.
  ps_bin=$(find $SRC -maxdepth 4 -type f -name "pscommand" -executable 2>/dev/null | head -1)
  if [ -n "$ps_bin" ]; then
    cp "$ps_bin" "ps-$suffix"
    strip "ps-$suffix" 2>/dev/null || true
    echo "  -> ps-$suffix ($(stat -c %s ps-$suffix) bytes)"
  fi
}

NC_X86="$(cd ../ncurses/install-x86_64 && pwd)"
NC_ARM="$(cd ../ncurses/install-aarch64 && pwd)"

build_one "x86_64"  "musl-gcc" \
  "$(uapi_cflags x86_64)" \
  "x86_64" "$NC_X86" "x86_64-linux-musl" "ar" "ranlib"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64" "$NC_ARM" "aarch64-linux-musl" "$CROSS_AR" "$CROSS_RANLIB"

echo "OK -- built procps-ng for {x86_64, aarch64}"
