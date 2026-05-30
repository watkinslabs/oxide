#!/usr/bin/sh
# Linux-PAM 1.7.2 build recipe — produces shared libpam.so.0 +
# libpam_misc.so.0 + PAM modules + unix_chkpwd helper for x86_64
# and aarch64. Distro layout. Login / sshd / su link against
# libpam.so dynamically; pam_unix.so etc. resolve all libpam
# symbols at dlopen() against the same libpam.so loaded in the
# process — no per-module libpam state, no -Bsymbolic hacks.
#
# Artifacts (per arch):
#   install-<arch>/lib/libpam.so.0 -> libpam.so.0.85.1   (sonamed)
#   install-<arch>/lib/libpam_misc.so.0 -> libpam_misc.so.0.82.1
#   install-<arch>/libpam.so + libpam_misc.so            (build-time symlinks)
#   install-<arch>/modules/{pam_unix,pam_permit,pam_deny,...}.so
#   install-<arch>/unix_chkpwd
#   install-<arch>/{security,include-security}/*.h
set -e

cd "$(dirname "$0")"
SRC="Linux-PAM-1.7.2"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-pam.sh first" >&2
  exit 1
fi

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

# We DO NOT patch shared_library → static_library this time. We want
# real shared libraries so login/sshd/su can dynamically link against
# them and modules can resolve their libpam refs at dlopen against
# the SAME copy of libpam.so loaded in the process.

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
c_link_args = []

[host_machine]
system = 'linux'
cpu_family = '$arch'
cpu = '$arch'
endian = 'little'
EOF
}

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
      --default-library shared \
      -Db_pie=false \
      -Db_lundef=false \
      -Db_staticpic=true \
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
    && ninja -C "$build" \
        libpam/libpam.so.0.85.1 \
        libpam_misc/libpam_misc.so.0.82.1 \
        modules/pam_unix/pam_unix.so \
        modules/pam_permit/pam_permit.so \
        modules/pam_deny/pam_deny.so \
        modules/pam_nologin/pam_nologin.so \
        modules/pam_warn/pam_warn.so \
        modules/pam_rootok/pam_rootok.so \
        modules/pam_unix/unix_chkpwd \
  )

  local outdir="install-$arch"
  rm -rf "$outdir"
  mkdir -p "$outdir/include-security" "$outdir/security" "$outdir/lib" "$outdir/modules"

  # Copy the versioned shared libs + their soname symlinks so that
  # downstream linkers (util-linux configure, sshd build) can find
  # -lpam and -lpam_misc via the unversioned .so soft links.
  # libpam.so.0.85.1 + libpam.so.0 -> libpam.so.0.85.1 + libpam.so -> libpam.so.0
  install_shared() {
    local sub="$1" stem="$2"
    local src_dir="$SRC/$build/$sub"
    local real
    real=$(cd "$src_dir" && ls "$stem".so* 2>/dev/null | grep -E '\.so\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ -z "$real" ]; then
      # Some meson configurations don't generate a fully versioned filename.
      real=$(cd "$src_dir" && ls "$stem".so* 2>/dev/null | grep -E '\.so\.[0-9]+$' | head -1)
    fi
    [ -z "$real" ] && real="$stem.so"
    cp "$src_dir/$real" "$outdir/lib/$real"
    # soname symlink (libpam.so.0)
    local soname
    soname=$(echo "$real" | sed -E 's/(\.so\.[0-9]+)\..*$/\1/')
    [ "$soname" != "$real" ] && ln -sf "$real" "$outdir/lib/$soname"
    # Linker symlink (libpam.so) at top-level for -L${pam_root} -lpam.
    ln -sf "lib/$real" "$outdir/$stem.so"
    [ "$soname" != "$real" ] && ln -sf "lib/$soname" "$outdir/$stem.so.0"
    echo "  → $outdir/lib/$real ($(stat -c %s "$outdir/lib/$real") bytes)"
  }
  install_shared "libpam"      "libpam"
  install_shared "libpam_misc" "libpam_misc"

  # PAM modules.
  for mod in pam_unix pam_permit pam_deny pam_nologin pam_warn pam_rootok; do
    local msrc="$SRC/$build/modules/$mod/$mod.so"
    if [ -f "$msrc" ]; then
      cp "$msrc" "$outdir/modules/$mod.so"
      "$strip" --strip-unneeded "$outdir/modules/$mod.so" 2>/dev/null || strip --strip-unneeded "$outdir/modules/$mod.so" 2>/dev/null || true
      echo "  → $outdir/modules/$mod.so"
    fi
  done

  # unix_chkpwd helper.
  if [ -f "$SRC/$build/modules/pam_unix/unix_chkpwd" ]; then
    cp "$SRC/$build/modules/pam_unix/unix_chkpwd" "$outdir/unix_chkpwd"
    "$strip" "$outdir/unix_chkpwd" 2>/dev/null || strip "$outdir/unix_chkpwd" 2>/dev/null || true
    echo "  → $outdir/unix_chkpwd"
  fi

  # Headers — staged under TWO paths for both `#include <pam_appl.h>` (-Ifoo/include-security)
  # and `#include <security/pam_appl.h>` (-Ifoo) include styles.
  for hdir in "$outdir/include-security" "$outdir/security"; do
    cp "$SRC/libpam/include/security/"*.h        "$hdir/"
    cp "$SRC/libpam_misc/include/security/"*.h   "$hdir/"
    cp "$SRC/libpamc/include/security/"*.h       "$hdir/"
    if [ -f "$SRC/$build/libpam/include/security/_pam_features.h" ]; then
      cp "$SRC/$build/libpam/include/security/_pam_features.h" "$hdir/"
    fi
  done
}

build_one "x86_64"  "_build-x86_64"  "cross-x86_64.ini"
build_one "aarch64" "_build-aarch64" "cross-aarch64.ini"

echo "OK — built install-{x86_64,aarch64}/lib/libpam{,_misc}.so.0 + modules/*.so + unix_chkpwd"
