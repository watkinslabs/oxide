#!/usr/bin/sh
# GNU bash 5.2.37 build recipe — pre-built static-musl binaries
# checked in as `vendor/bash/bash-{x86_64,aarch64}`.
#
# F216: first GNU userspace program cross-built into the rootfs as a
# distro-pathway shakedown. bash exercises a much wider libc surface
# than busybox-ash (full signal handling, job control via TIOCSPGRP,
# fork+exec patterns, /dev/tty fallback, alarm-based read timeouts);
# every gap surfaces a kernel/libc fix that lands in the same PR.
#
# Build is minimal: --disable-nls, --without-bash-malloc (use musl's),
# --disable-net-redirections (no /dev/tcp), --disable-help-builtin.
# readline + history ARE enabled (interactive line editing, tab
# completion, history, arrow keys) using bash's BUNDLED readline +
# termcap (bash_cv_termcap_lib=gnutermcap) so the static musl link needs
# no external libtinfo. Static link so the binary works pre-dynamic-linker.
set -e

cd "$(dirname "$0")"
. ../lib/uapi-stage.sh
SRC="bash-5.2.37"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-bash.sh first" >&2
  exit 1
fi

# musl-gcc lacks Linux UAPI headers; stage host copies into a private
# tree and -isystem them (same approach as busybox/openssh).
HDRS_X86=/tmp/musl-hdrs-bash
mkdir -p "$HDRS_X86"
for d in linux asm asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_X86/$d" || cp -r "/usr/include/$d" "$HDRS_X86/$d" 2>/dev/null || true
done

HDRS_ARM=/tmp/musl-hdrs-bash-arm
mkdir -p "$HDRS_ARM"
for d in linux asm-generic mtd scsi sound rdma xen misc; do
  test -d "$HDRS_ARM/$d" || cp -r "/usr/include/$d" "$HDRS_ARM/$d" 2>/dev/null || true
done

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"

cleanup_objs() {
  ( cd "$SRC" && make clean >/dev/null 2>&1 || true )
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
}

# bash autoconf cross-build requires pre-seeded config.cache for the
# guard tests it can't run on the host (rl_completion_append_character
# detection etc.). The classic recipe per bash INSTALL § "Cross-compiling":
config_cache() {
  cat > config.cache <<'EOF'
ac_cv_func_mmap_fixed_mapped=yes
ac_cv_func_strcoll_works=yes
ac_cv_func_working_mktime=yes
ac_cv_func_setvbuf_reversed=no
ac_cv_func_getcwd_null=yes
ac_cv_have_decl_sys_siglist=no
ac_cv_func_posix_getpwuid_r=yes
ac_cv_func_dev_fd=no
ac_cv_rl_version=8.2
bash_cv_func_sigsetjmp=present
bash_cv_must_reinstall_sighandlers=no
bash_cv_func_strcoll_broken=no
bash_cv_under_sys_siglist=no
bash_cv_sys_siglist=no
bash_cv_unusable_rtsigs=no
bash_cv_dup2_broken=no
bash_cv_pgrp_pipe=no
bash_cv_type_rlimit=long
bash_cv_decl_under_sys_siglist=no
bash_cv_getcwd_malloc=yes
bash_cv_getenv_redef=yes
bash_cv_func_ctype_nonascii=yes
bash_cv_termcap_lib=gnutermcap
bash_cv_wcwidth_broken=no
ac_cv_c_long_double=yes
EOF
}

build_one() {
  arch="$1"; cc="$2"; extra="$3"; suffix="$4"
  echo "=== building bash for $arch ==="
  cleanup_objs
  config_cache
  cp config.cache "$SRC/config.cache"
  # bash 5.2 has K&R-style defs (old-style) that GCC 15+ rejects under
  # the new C23 default. -std=gnu89 keeps the legacy behaviour; the
  # extra -Wno-* silence the warning torrent so real errors stand out.
  # Also pass CC_FOR_BUILD CFLAGS so the host-side mkbuiltins build
  # tool gets the same legacy-C treatment.
  ( cd "$SRC" && \
    CC="$cc" \
    CC_FOR_BUILD="gcc" \
    CFLAGS_FOR_BUILD="-std=gnu89 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
    LDFLAGS_FOR_BUILD="" \
    CFLAGS="-Os -std=gnu89 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types $extra" \
    LDFLAGS="" \
    ./configure \
      --host="${arch}-linux-musl" \
      --cache-file=config.cache \
      --without-bash-malloc \
      --disable-nls \
      --enable-readline \
      --enable-history \
      --disable-net-redirections \
      --disable-help-builtin \
      --prefix=/usr \
    && make -j4 bash \
  )
  cp "$SRC/bash" "bash-$suffix"
  strip "bash-$suffix" 2>/dev/null || true
  echo "  → bash-$suffix  ($(stat -c %s "bash-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"  "$(uapi_cflags x86_64)" "x86_64"
build_one "aarch64" "$CROSS_CC" "$(uapi_cflags aarch64)" "aarch64"

echo "OK — built bash for {x86_64, aarch64}"
