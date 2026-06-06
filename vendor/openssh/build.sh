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
. ../lib/uapi-stage.sh
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
  local pam_root="$(pwd)/../pam/install-${arch}"
  local zlib_root="$(pwd)/../zlib/install-${arch}"
  echo "=== building openssh for $arch (with PAM + zlib) ==="
  cleanup_objs
  # Pre-seed autoconf cache for cross-compile so configure stops
  # guessing. All values reflect Linux/musl reality on our targets:
  #   - setresuid/setresgid work (we have B13 cap-emulate-setxuid)
  #   - snprintf/vsnprintf correct (musl)
  #   - utf-8 locales (musl supports C.UTF-8)
  #   - SA_RESTART interrupts select() (Linux behavior)
  #   - fflush(NULL), calloc(0,N) work as POSIX says
  #   - /dev/ptmx + /dev/urandom + /dev/random exist (verified at runtime)
  #   - struct dirent has space for full d_name (musl: char[256])
  cat > "$SRC/config.cache" <<EOF
ac_cv_func_setresuid=yes
ac_cv_func_setresgid=yes
ac_cv_func_snprintf=yes
ac_cv_func_vsnprintf=yes
ac_cv_func_strnvis=no
ac_cv_have_decl___VA_OPT__=yes
ac_cv_have_devurandom=yes
ssh_cv_signal_sigchld_eintr_select=yes
ssh_cv_calloc_zero=yes
ssh_cv_func_fflush_null_works=yes
ssh_cv_libc_defines_sys_errlist=yes
ssh_cv_libc_defines_sys_nerr=yes
ssh_cv_dirent_d_name_size_ok=yes
ssh_cv_snprintf_overflow_handled=yes
ssh_cv_have_utf8_locale=yes
ac_cv_lib_z_deflate=yes
ac_cv_var_dev_ptmx=/dev/ptmx
ac_cv_dev_ptmx=yes
EOF
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os $extra -I${pam_root} -I${zlib_root}/include -DUNSUPPORTED_POSIX_THREADS_HACK" \
    LDFLAGS="-L${pam_root} -L${pam_root}/lib -L${zlib_root}/lib -Wl,-rpath,/usr/lib" \
    LIBS="-lpam -lpam_misc -lz -lpthread" \
    ./configure \
      --cache-file=config.cache \
      --host="${arch}-linux-musl" \
      --without-openssl \
      --with-zlib="${zlib_root}" \
      --with-pam \
      --without-selinux \
      --without-libedit \
      --without-audit \
      --without-rpath \
      --with-privsep-user=root \
      --with-privsep-path=/var/empty \
      --with-sandbox=no \
      --with-maildir=/var/mail \
      --with-default-path=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
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
  "$(uapi_cflags x86_64)" \
  "x86_64"

build_one "aarch64" "$CROSS_CC" \
  "$(uapi_cflags aarch64)" \
  "aarch64"

echo "OK — built sshd/ssh/ssh-keygen for {x86_64, aarch64}"
