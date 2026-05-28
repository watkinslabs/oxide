#!/usr/bin/sh
# OpenSSH 9.9p2 build recipe — pre-built static-musl binaries
# checked in as `vendor/openssh/sshd-{x86_64,aarch64}` plus the
# matching ssh client + ssh-keygen helpers (used at runtime to
# generate per-boot host keys on the rootfs).
#
# F210: oxide2 replaces dropbear with openssh-portable.
# dropbear's check_close → close-PTY-master on CHANNEL_EOF arm
# loses shell stdout when `ssh -tt 'cmd'` runs with closed stdin
# (a defect that reproduces on real Linux too, not just our
# kernel). openssh's send-eof + drain semantic handles that case
# correctly.
#
# Feature set (built without OpenSSL — uses internal limited
# crypto: chacha20-poly1305 + curve25519 + ed25519. Modern SSH
# default cipher suite covers these; no RSA / ECDSA / AES.):
#   --without-openssl       — internal crypto only
#   --without-zlib          — no compression
#   --disable-strip         — static-musl strip is broken w/ cross
#
# Re-run this to rebuild against fresh upstream (run
# tools/fetch-openssh.sh first to populate the source tree).
set -e

cd "$(dirname "$0")"
SRC="openssh-9.9p2"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-openssh.sh first" >&2
  exit 1
fi

# musl-gcc lacks Linux UAPI headers; stage host copies into a private
# tree and -isystem them (same approach as busybox/dhcpcd/dropbear).
HDRS_X86=/tmp/musl-hdrs-openssh
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-openssh-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done
# aarch64 cross toolchain (we cd'd into vendor/openssh earlier).
CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make clean >/dev/null 2>&1 || true )
}

# OpenSSH binaries we ship: sshd (server), ssh (client, for debug),
# ssh-keygen (run at first boot to generate per-host keys).
# scp/sftp/ssh-add/ssh-agent skipped — not used in v1.
PROGRAMS="sshd sshd-session ssh ssh-keygen"

build_one() {
  local arch="$1" cc="$2" extra="$3" suffix="$4"
  echo "=== building openssh for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -static $extra" \
    LDFLAGS="-static" \
    ./configure \
      --host="${arch}-linux-musl" \
      --without-openssl \
      --without-zlib \
      --without-pam \
      --without-selinux \
      --without-libedit \
      --without-audit \
      --without-rpath \
      --with-privsep-user=root \
      --with-privsep-path=/var/empty \
      --with-sandbox=no \
      --prefix=/usr \
      --sysconfdir=/etc/ssh \
      --libexecdir=/usr/libexec \
      --enable-dsa-keys=no \
    && make $PROGRAMS -j4 \
  )
  for p in $PROGRAMS; do
    cp "$SRC/$p" "$p-$suffix"
    strip "$p-$suffix" 2>/dev/null || true
    echo "  → $p-$suffix  ($(stat -c %s "$p-$suffix") bytes)"
  done
}

build_one "x86_64"  "musl-gcc" \
  "-isystem $HDRS_X86" \
  "x86_64"

build_one "aarch64" "$CROSS_CC" \
  "-isystem $HDRS_ARM" \
  "aarch64"

echo "OK — built sshd/ssh/ssh-keygen for {x86_64, aarch64}"
