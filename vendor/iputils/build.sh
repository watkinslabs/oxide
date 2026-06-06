#!/usr/bin/sh
# iputils 20240117 build recipe -- D5 of distro roadmap.
# Static-musl. ping, tracepath, clockdiff, arping.
# meson/ninja build. Optional deps (libcap, libidn2, gettext) off so
# configure cannot pull host shared libs into a -static link.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="iputils-20240117"
if [ ! -d "$SRC" ]; then
  echo "missing $SRC -- run tools/fetch-iputils.sh first" >&2
  exit 1
fi

# musl folds the resolver into libc -- there is no libresolv.a, so a
# static `find_library('resolv')` fails. Make it optional; a not-found
# dep is a no-op in the ping link, the symbols come from libc.
sed -i "s/cc.find_library('resolv')/cc.find_library('resolv', required : false)/" \
  "$SRC/meson.build"

# musl-gcc ships libc headers only; iputils needs kernel headers
# (linux/types.h, linux/errqueue.h, linux/if_ether.h). Stage host
# kernel headers under -isystem dirs. x86 takes asm/ from the host;
# aarch64 takes asm/ from the cross toolchain sysroot (so skip it).
HDRS_X86=/tmp/musl-hdrs-iputils
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-iputils-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_AR="$CROSS_ROOT/bin/aarch64-linux-musl-ar"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

# meson native file: build the host arch with musl-gcc, not cc.
NATIVE=/tmp/iputils-native-musl.ini
cat > "$NATIVE" <<EOF
[binaries]
c = 'musl-gcc'
ar = 'ar'
strip = 'strip'

[built-in options]
c_args = ['-Os', '-isystem', '$HDRS_X86']
c_link_args = ['-static']
EOF

# meson cross file for aarch64-linux-musl.
CROSS=/tmp/iputils-cross-aarch64.ini
cat > "$CROSS" <<EOF
[binaries]
c = '$CROSS_CC'
ar = '$CROSS_AR'
strip = '$CROSS_STRIP'

[built-in options]
c_args = ['-Os']
c_link_args = ['-static']

[host_machine]
system = 'linux'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'
EOF

OPTS="-Dprefer_static=true --default-library=static \
  -DUSE_CAP=false -DUSE_IDN=false -DUSE_GETTEXT=false \
  -DBUILD_MANS=false -DBUILD_HTML_MANS=false \
  -DBUILD_PING=true -DBUILD_TRACEPATH=true \
  -DBUILD_CLOCKDIFF=true -DBUILD_ARPING=true \
  -DNO_SETCAP_OR_SUID=true -DSKIP_TESTS=true \
  -DINSTALL_SYSTEMD_UNITS=false"

build_one() {
  arch="$1"; file_flag="$2"; suffix="$3"
  echo "=== building iputils for $arch ==="
  rm -rf "build-$suffix"
  # shellcheck disable=SC2086
  meson setup "build-$suffix" "$SRC" $file_flag $OPTS
  ninja -C "build-$suffix"
  for b in ping tracepath clockdiff arping; do
    found="build-$suffix/$b"
    [ -f "$found" ] || continue
    cp "$found" "$b-$suffix"
    strip "$b-$suffix" 2>/dev/null || true
    echo "  -> $b-$suffix ($(stat -c %s "$b-$suffix") bytes)"
  done
}

build_one "x86_64"  "--native-file $NATIVE" "x86_64"
build_one "aarch64" "--cross-file $CROSS"   "aarch64"

echo "OK -- built iputils for {x86_64, aarch64}"
