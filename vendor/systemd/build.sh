#!/usr/bin/sh
# systemd 259 musl cross-build — per-arch libsystemd-shared + libsystemd
# under vendor/systemd/install-<arch>/{lib,include}. Track D6.
# Validated config + musl-gap notes: research/systemd-build.md.
# Incremental: this stage builds the two core .so's; PID1 + units later.
set -e
cd "$(dirname "$0")"
SRC="systemd-259"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-systemd.sh first" >&2; exit 1; }
ROOT="$(cd .. && pwd)"                         # vendor/
SHIM="$(pwd)/musl-shims"
CROSSDIR="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"

OPTS="-Dlibc=musl -Dmode=release \
-Dkmod=enabled -Dseccomp=enabled -Dopenssl=enabled -Dblkid=enabled -Dacl=enabled -Dlibidn2=enabled \
-Dgcrypt=disabled -Dtpm2=disabled -Dlibfido2=disabled -Dpwquality=disabled -Dp11kit=disabled \
-Dlibcryptsetup=disabled -Dbpf-framework=disabled -Dvmspawn=disabled -Dmicrohttpd=disabled \
-Dqrencode=disabled -Dgnutls=disabled -Dxkbcommon=disabled -Dselinux=disabled -Dapparmor=disabled \
-Dsmack=false -Dlibcurl=disabled -Delfutils=disabled -Dlibidn=disabled -Dpam=disabled -Dfdisk=disabled \
-Dbzip2=disabled -Dlibarchive=disabled -Dxz=disabled -Dlz4=disabled -Dzlib=disabled -Dzstd=disabled \
-Dgshadow=false -Dima=false -Defi=false -Dbootloader=disabled -Dhomed=disabled -Drepart=disabled \
-Dsysupdate=disabled -Dukify=disabled -Dman=false -Dhtml=false"

build_one() {
  arch="$1"; cc="$2"; extra_cflags="$3"
  install="install-${arch}"
  bdir="${SRC}/build-${arch}"
  echo "=== systemd cross-build for $arch ==="
  ./gen-pc.sh "$arch" >/dev/null
  # Per-arch pkg_config_libdir = ONLY our staged L2 pkgconfig dirs.
  pcdirs=""
  for v in libcap libseccomp kmod libgpg-error libgcrypt openssl util-linux acl attr libidn2 pcre2 zstd lz4 zlib; do
    pcdirs="${pcdirs}:${ROOT}/${v}/install-${arch}/lib/pkgconfig"
  done
  pcdirs="${pcdirs#:}"
  cross="/tmp/oxide-systemd-cross-${arch}.txt"
  cat > "$cross" <<EOF
[binaries]
c = '${cc}'
ar = 'ar'
strip = 'strip'
pkg-config = 'pkg-config'
[host_machine]
system = 'linux'
cpu_family = '${arch}'
cpu = '${arch}'
endian = 'little'
[built-in options]
c_args = [${extra_cflags}'-I${SHIM}']
[properties]
pkg_config_libdir = '${pcdirs}'
EOF
  rm -rf "$bdir"
  ( cd "$SRC" && meson setup "build-${arch}" --cross-file "$cross" $OPTS >/dev/null )
  ninja -C "$bdir" src/shared/libsystemd-shared-259.so libsystemd.so.0.42.0 >/dev/null
  rm -rf "$install"; mkdir -p "$install/lib"
  cp -L "$bdir/src/shared/libsystemd-shared-259.so" "$install/lib/"
  cp -L "$bdir/libsystemd.so.0.42.0" "$install/lib/libsystemd.so.0.42.0"
  ( cd "$install/lib" && ln -sf libsystemd.so.0.42.0 libsystemd.so.0 && ln -sf libsystemd.so.0 libsystemd.so )
  # public sd-*.h headers for the probe.
  mkdir -p "$install/include/systemd"
  cp "$SRC"/src/systemd/*.h "$install/include/systemd/" 2>/dev/null || true
  echo "  → $install/lib/libsystemd-shared-259.so + libsystemd.so.0.42.0"
}

# x86: musl-gcc + -idirafter for kernel UAPI. arm: cross gcc, sysroot has UAPI.
build_one "x86_64"  "musl-gcc" "'-idirafter', '/usr/include', "
build_one "aarch64" "${CROSSDIR}/aarch64-linux-musl-gcc" "'-idirafter', '/usr/include', "
