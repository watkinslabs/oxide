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

# Stage modern generic Linux UAPI (struct statx etc.) into the shim so a
# HIGH-priority -I<shim> overrides the aarch64-linux-musl-cross sysroot's
# pre-statx <linux/stat.h>. Generic linux/ UAPI is arch-independent; we do
# NOT copy asm/ (arch-specific — the cross sysroot's asm/ stays correct).
# Build-time copy from the host kernel-headers (not committed). Copy ONLY
# the headers needed for struct statx — copying all of linux/ drags in
# headers with glibc-context deps (e.g. vm_sockets.h needs struct sockaddr)
# that break the musl compile.
if [ -d /usr/include/linux ]; then
  rm -rf "$SHIM/linux"; mkdir -p "$SHIM/linux"
  for h in stat.h types.h posix_types.h; do
    [ -f "/usr/include/linux/$h" ] && cp "/usr/include/linux/$h" "$SHIM/linux/"
  done
fi

OPTS="-Dlibc=musl -Dmode=release \
-Dkmod=enabled -Dseccomp=enabled -Dopenssl=enabled -Dblkid=enabled -Dacl=enabled -Dlibidn2=enabled \
-Dgcrypt=disabled -Dtpm2=disabled -Dlibfido2=disabled -Dpwquality=disabled -Dp11kit=disabled \
-Dlibcryptsetup=disabled -Dbpf-framework=disabled -Dvmspawn=disabled -Dmicrohttpd=disabled \
-Dqrencode=disabled -Dgnutls=disabled -Dxkbcommon=disabled -Dselinux=disabled -Dapparmor=disabled \
-Dsmack=false -Dlibcurl=disabled -Delfutils=disabled -Dlibidn=disabled -Dpam=disabled -Dfdisk=disabled \
-Dbzip2=disabled -Dlibarchive=disabled -Dxz=disabled -Dlz4=disabled -Dzlib=disabled -Dzstd=disabled \
-Dgshadow=false -Dima=false -Defi=false -Dbootloader=disabled -Dhomed=disabled -Drepart=disabled \
-Dsysupdate=disabled -Dukify=disabled -Dman=false -Dhtml=false"

# The aarch64-linux-musl-cross toolchain's musl predates statx (musl
# 1.2.0); systemd uses struct statx unconditionally. Backport it into the
# toolchain's <sys/stat.h> once (reproducible; toolchain is fetched, not
# committed).
ARM_STAT="${CROSSDIR}/../aarch64-linux-musl/include/sys/stat.h"
if [ -f "$ARM_STAT" ] && ! grep -q "struct statx" "$ARM_STAT"; then
  cat "$SHIM/statx-backport.h" >> "$ARM_STAT"
  echo "patched arm musl sys/stat.h with statx backport"
fi

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
  # Global L2 include dirs in c_args: meson propagates pkg-config dep
  # Cflags to libshared but not always to libcore/executables (e.g.
  # exec-credential.c includes <acl/libacl.h>); provide all L2 headers
  # globally so every systemd target finds them (linking still via pkg-config).
  l2incs=""
  for v in libcap libseccomp kmod libgpg-error libgcrypt openssl acl attr libidn2 pcre2 zstd lz4; do
    l2incs="${l2incs}, '-I${ROOT}/${v}/install-${arch}/include'"
  done
  for sub in blkid libmount uuid libsmartcols ""; do
    l2incs="${l2incs}, '-I${ROOT}/util-linux/install-${arch}/include/${sub}'"
  done
  # arm: the old cross musl has no statx() symbol; link a tiny syscall
  # wrapper (systemd 259 calls statx() unconditionally). x86 musl has it.
  linkargs=""
  if [ "$arch" = "aarch64" ]; then
    "$cc" -O2 -c "$SHIM/statx-wrapper.c" -o "$SHIM/statx-${arch}.o"
    # Strict arm cross-ld must resolve libsystemd-shared.so's transitive
    # DT_NEEDED (libcrypto etc.) when linking the executables → -rpath-link
    # at every L2 libdir (same pattern as dyn_probe / the libgcrypt build).
    rpl=""
    for v in libcap libseccomp kmod libgpg-error libgcrypt openssl util-linux acl attr libidn2 pcre2 zstd lz4 zlib; do
      rpl="${rpl}, '-Wl,-rpath-link,${ROOT}/${v}/install-${arch}/lib'"
    done
    linkargs="c_link_args = ['$SHIM/statx-${arch}.o'${rpl}]"
  fi
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
c_args = [${extra_cflags}'-I${SHIM}'${l2incs}]
${linkargs}
[properties]
pkg_config_libdir = '${pcdirs}'
EOF
  rm -rf "$bdir"
  ( cd "$SRC" && meson setup "build-${arch}" --cross-file "$cross" $OPTS >/dev/null )
  ninja -C "$bdir" src/shared/libsystemd-shared-259.so libsystemd.so.0.42.0 src/core/libsystemd-core-259.so systemd systemd-executor systemctl >/dev/null
  rm -rf "$install"; mkdir -p "$install/lib"
  cp -L "$bdir/src/shared/libsystemd-shared-259.so" "$install/lib/"
  cp -L "$bdir/libsystemd.so.0.42.0" "$install/lib/libsystemd.so.0.42.0"
  ( cd "$install/lib" && ln -sf libsystemd.so.0.42.0 libsystemd.so.0 && ln -sf libsystemd.so.0 libsystemd.so )
  # PID1 + its private libs + systemctl. systemd binary DT_NEEDEDs
  # libsystemd-core-259.so + libsystemd-shared-259.so (both staged here).
  cp -L "$bdir/src/core/libsystemd-core-259.so" "$install/lib/"
  mkdir -p "$install/lib/systemd" "$install/bin"
  cp -L "$bdir/systemd"   "$install/lib/systemd/systemd"
  # systemd 259 splits service-spawning into a separate executor binary
  # that manager_new() pins at SYSTEMD_EXECUTOR_BINARY_PATH
  # (/usr/lib/systemd/systemd-executor); absent ⇒ "Failed to pin executor
  # binary" ⇒ PID1 freezes. Staged to /usr/lib/systemd/ by l2_deps.
  cp -L "$bdir/systemd-executor" "$install/lib/systemd/systemd-executor"
  cp -L "$bdir/systemctl" "$install/bin/systemctl"
  # public sd-*.h headers for the probe.
  mkdir -p "$install/include/systemd"
  cp "$SRC"/src/systemd/*.h "$install/include/systemd/" 2>/dev/null || true
  # F350 #5: minimal systemd unit tree so PID1 has a default.target to load
  # (else it wedges right after unit-type enumeration). Uses systemd's own
  # static .target units + a custom default.target that pulls the chain and
  # a console-shell (systemd debug-shell pattern, /bin/sh on /dev/console)
  # for first light. ninja/meson install can't be used (rebuilds broken
  # tests / installs unbuilt udevadm), so stage the static targets directly.
  local sysd="$install/usr/lib/systemd/system"
  mkdir -p "$sysd"
  for t in sysinit.target basic.target multi-user.target getty.target \
           sockets.target paths.target slices.target timers.target \
           local-fs.target local-fs-pre.target swap.target getty-pre.target \
           graphical.target rescue.target emergency.target; do
    cp -L "$SRC/units/$t" "$sysd/$t" 2>/dev/null || true
  done
  cat > "$sysd/console-shell.service" <<'UNIT'
[Unit]
Description=Console Shell (oxide first light)
Documentation=man:systemd-debug-generator(8)
DefaultDependencies=no
ConditionPathExists=/dev/console
[Service]
Environment=TERM=linux
ExecStart=/bin/sh
Restart=always
RestartSec=1
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TTYReset=yes
KillMode=process
IgnoreSIGPIPE=no
[Install]
WantedBy=multi-user.target
UNIT
  cat > "$sysd/default.target" <<'UNIT'
[Unit]
Description=Oxide Default Target
Documentation=man:systemd.special(7)
Requires=basic.target
Wants=console-shell.service
After=basic.target
AllowIsolate=yes
UNIT
  echo "  → $install: libsystemd-shared + libsystemd + libsystemd-core + /lib/systemd/systemd + systemd-executor + systemctl + unit tree"
}

# x86: musl-gcc + -idirafter for kernel UAPI. arm: cross gcc, sysroot has UAPI.
build_one "x86_64"  "musl-gcc" "'-idirafter', '/usr/include', "
build_one "aarch64" "${CROSSDIR}/aarch64-linux-musl-gcc" "'-idirafter', '/usr/include', "
