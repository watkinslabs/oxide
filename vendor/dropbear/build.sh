#!/usr/bin/sh
# Dropbear 2024.86 build recipe — pre-built static-musl binaries
# checked in as `vendor/dropbear/dropbearmulti-x86_64` and
# `vendor/dropbear/dropbearmulti-aarch64`. Multi-binary form: one ELF
# dispatches on argv[0] into dropbear/dbclient/dropbearkey/scp/etc.
#
# Re-run this to rebuild against fresh upstream (run
# tools/fetch-dropbear.sh first to populate the source tree).
#
# Feature set:
#   --disable-syslog       — no syslog daemon in v1
#   --disable-utmp/wtmp    — no user-accounting db
#   --disable-lastlog
#   --disable-zlib         — keep size small, no compression
#   --disable-pam          — no PAM (passwd + crypt only)
#   --enable-static        — static-musl binary
#
# localoptions.h trims further: server-only, password auth only,
# minimal cipher set.
set -e

cd "$(dirname "$0")"
SRC="dropbear-2024.86"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-dropbear.sh first" >&2
  exit 1
fi

# musl-gcc lacks Linux UAPI headers; stage host copies into a private
# tree and -isystem them (same approach as busybox/dhcpcd builds).
HDRS_X86=/tmp/musl-hdrs-dropbear
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-dropbear-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done
# aarch64 cross toolchain (we cd'd into vendor/dropbear earlier).
CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

# F196: trim defaults via localoptions.h. Server-only password auth,
# small cipher set, no scp/sftp/agent forwarding, no X11 forwarding.
cat > "$SRC/localoptions.h" <<'EOF'
/* F196: oxide2 trimmed dropbear server build.
 * - server only
 * - password auth only (no pubkey for v1)
 * - minimal cipher/MAC set (chacha20-poly1305 + aes128-ctr + sha2-256)
 * - drop scp/sftp + agent + X11 forwarding
 */
#define DROPBEAR_CLI_PASSWORD_AUTH 0
#define DROPBEAR_CLI_PUBKEY_AUTH   0
#define DROPBEAR_SVR_PASSWORD_AUTH 1
#define DROPBEAR_SVR_PUBKEY_AUTH   1
#define DROPBEAR_USE_PASSWORD_ENV  0
#define DROPBEAR_CLIENT 0
#define DROPBEAR_X11FWD 0
#define DROPBEAR_AGENTFWD 0
#define DROPBEAR_AES256 0
#define DROPBEAR_AES128 1
#define DROPBEAR_CHACHA20POLY1305 1
#define DROPBEAR_3DES 0
#define DROPBEAR_TWOFISH256 0
#define DROPBEAR_TWOFISH128 0
#define DROPBEAR_SHA1_HMAC 0
#define DROPBEAR_SHA1_96_HMAC 0
#define DROPBEAR_SHA2_256_HMAC 1
#define DROPBEAR_SHA2_512_HMAC 0
#define DROPBEAR_ED25519 1
#define DROPBEAR_RSA 1
#define DROPBEAR_DSS 0
#define DROPBEAR_ECDSA 0
#define DROPBEAR_CURVE25519 1
#define DROPBEAR_DH_GROUP14_SHA256 1
#define DROPBEAR_DH_GROUP14_SHA1 0
#define DROPBEAR_DH_GROUP1 0
/* Disable user-accounting databases we don't ship. */
#define DROPBEAR_LASTLOG 0
#define DO_MOTD 0
EOF

cleanup_objs() {
  ( cd "$SRC" && make clean >/dev/null 2>&1 || true )
}

build_one() {
  local arch="$1" cc="$2" extra="$3" out="$4"
  echo "=== building dropbear for $arch ==="
  cleanup_objs
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -static $extra" \
    LDFLAGS="-static" \
    ./configure \
      --host="${arch}-linux-musl" \
      --disable-zlib \
      --disable-syslog \
      --disable-utmp --disable-utmpx \
      --disable-wtmp  --disable-wtmpx \
      --disable-lastlog \
      --disable-pam \
      --disable-pututline --disable-pututxline \
      --enable-static \
    && make PROGRAMS="dropbear dropbearkey" MULTI=1 -j4 \
  )
  cp "$SRC/dropbearmulti" "$out"
  strip "$out" 2>/dev/null || true
  echo "  → $out  ($(stat -c %s "$out") bytes)"
}

build_one "x86_64"  "musl-gcc" \
  "-isystem $HDRS_X86" \
  "dropbearmulti-x86_64"

build_one "aarch64" "$CROSS_CC" \
  "-isystem $HDRS_ARM" \
  "dropbearmulti-aarch64"

echo "OK — built dropbearmulti-{x86_64,aarch64}"
