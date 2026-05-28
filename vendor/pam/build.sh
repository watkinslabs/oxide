#!/usr/bin/sh
# Linux-PAM 1.7.2 build recipe — produces static-musl libpam.a +
# libpam_misc.a + PAM headers for x86_64 and aarch64.
#
# Artifacts (per arch):
#   vendor/pam/install-<arch>/libpam.a
#   vendor/pam/install-<arch>/libpam_misc.a
#   vendor/pam/install-<arch>/include-security/*.h
#
# Re-run this to rebuild against fresh upstream (run
# tools/fetch-pam.sh first to populate the source tree).
#
# Upstream switched to meson in 1.7; we sed-patch shared_library →
# static_library in libpam/libpam_misc and strip the version-script
# link_args (ld --version-script is shared-only). PAM modules and
# loadable-module machinery are not built — apps that need a single
# static binary embedding pam_unix/pam_deny/pam_permit/pam_nologin
# link those .o files directly.
set -e

cd "$(dirname "$0")"
SRC="Linux-PAM-1.7.2"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-pam.sh first" >&2
  exit 1
fi

# musl-gcc lacks Linux UAPI headers; stage host copies into a private
# tree and -isystem them (same approach as busybox/dropbear builds).
HDRS_X86=/tmp/musl-hdrs-pam
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-pam-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_AR="$CROSS_ROOT/bin/aarch64-linux-musl-ar"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

# --- Patch shared_library → static_library in libpam + libpam_misc.
# Idempotent: skip if already patched.
patch_meson_static() {
  local f="$1"
  if grep -q 'shared_library' "$f"; then
    # Drop link_args / link_depends / version kwargs which are
    # shared-only or unsupported for static_library. Easiest: rewrite
    # the link_args line to no-op, strip version line, swap call name.
    sed -i \
      -e 's/shared_library/static_library/' \
      -e "s|link_args: libpam_link_args,|link_args: [], pic: true,|" \
      -e "s|link_args: libpam_misc_link_args,|link_args: [], pic: true,|" \
      -e "s|link_args: libpamc_link_args,|link_args: [], pic: true,|" \
      -e '/^  version: libpam_version,$/d' \
      -e '/^  version: libpam_misc_version,$/d' \
      -e '/^  version: libpamc_version,$/d' \
      -e '/^  link_depends: libpam_link_deps,$/d' \
      -e '/^  link_depends: libpam_misc_link_deps,$/d' \
      -e '/^  link_depends: libpamc_link_deps,$/d' \
      "$f"
  fi
}

patch_meson_static "$SRC/libpam/meson.build"
patch_meson_static "$SRC/libpam_misc/meson.build"
patch_meson_static "$SRC/libpamc/meson.build"

# libpam_internal needs pic:true so PAM modules (shared_module) can
# link it. Modules themselves stay shared — we don't install them,
# we just need configure to succeed so libpam/libpam_misc build.
if ! grep -q "pic: true" "$SRC/libpam_internal/meson.build"; then
  sed -i "s|dependencies: libeconf,|dependencies: libeconf, pic: true,|" \
    "$SRC/libpam_internal/meson.build"
fi

# Disable PIE for static archives + drop b_lundef (we're not linking
# the shared lib).
write_cross_file() {
  local arch="$1" cc="$2" ar="$3" strip="$4" cflags="$5" out="$6"
  cat > "$out" <<EOF
[binaries]
c = '$cc'
ar = '$ar'
strip = '$strip'
pkg-config = 'false'

[built-in options]
c_args = [$cflags]
c_link_args = ['-static']

[host_machine]
system = 'linux'
cpu_family = '$arch'
cpu = '$arch'
endian = 'little'
EOF
}

# Comma-quoted list of -isystem flags for the cross file.
hdr_flags_x86="'-isystem', '$HDRS_X86', '-Os', '-D_GNU_SOURCE'"
hdr_flags_arm="'-isystem', '$HDRS_ARM', '-Os', '-D_GNU_SOURCE'"

write_cross_file "x86_64"  "musl-gcc"   "ar"        "strip"        "$hdr_flags_x86" "$SRC/cross-x86_64.ini"
write_cross_file "aarch64" "$CROSS_CC"  "$CROSS_AR" "$CROSS_STRIP" "$hdr_flags_arm" "$SRC/cross-aarch64.ini"

build_one() {
  local arch="$1" build="$2" cross_ini="$3"
  echo "=== building Linux-PAM for $arch ==="
  rm -rf "$SRC/$build"
  ( cd "$SRC" && \
    meson setup "$build" \
      --cross-file "$cross_ini" \
      --buildtype plain \
      --default-library static \
      -Db_pie=false \
      -Db_lundef=false \
      -Db_staticpic=false \
      -Ddocs=disabled \
      -Daudit=disabled \
      -Dselinux=disabled \
      -Dnis=disabled \
      -Di18n=disabled \
      -Dlogind=disabled \
      -Delogind=disabled \
      -Deconf=disabled \
      -Dpwaccess=disabled \
      -Dopenssl=disabled \
      -Dpam_userdb=disabled \
      -Dpam_lastlog=disabled \
      -Dpam_unix=auto \
      -Dexamples=false \
      -Dxtests=false \
      --prefix=/usr \
      --libdir=lib \
      --sysconfdir=/etc \
    && ninja -C "$build" libpam/libpam.a libpam_misc/libpam_misc.a \
  )

  local outdir="install-$arch"
  rm -rf "$outdir"
  mkdir -p "$outdir/include-security"
  cp "$SRC/$build/libpam/libpam.a"           "$outdir/libpam.a"
  cp "$SRC/$build/libpam_misc/libpam_misc.a" "$outdir/libpam_misc.a"
  # Headers live in libpam/include/security/*.h (public PAM API).
  cp "$SRC/libpam/include/security/"*.h      "$outdir/include-security/"
  # _pam_features.h is generated under the build tree.
  if [ -f "$SRC/$build/libpam/include/security/_pam_features.h" ]; then
    cp "$SRC/$build/libpam/include/security/_pam_features.h" "$outdir/include-security/"
  fi
  echo "  → $outdir/libpam.a        ($(stat -c %s "$outdir/libpam.a") bytes)"
  echo "  → $outdir/libpam_misc.a   ($(stat -c %s "$outdir/libpam_misc.a") bytes)"
}

build_one "x86_64"  "_build-x86_64"  "cross-x86_64.ini"
build_one "aarch64" "_build-aarch64" "cross-aarch64.ini"

echo "OK — built install-{x86_64,aarch64}/libpam{,misc}.a + headers"
