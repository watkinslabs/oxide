#!/usr/bin/sh
# jq 1.7.1 build recipe — pre-built static-musl binaries checked in as
# vendor/jq/jq-{x86_64,aarch64}. Drops in at /usr/bin/jq.
#
# jq is the JSON processor used by distro scripts/tooling. The release
# tarball bundles oniguruma (regex) via --with-oniguruma=builtin, so the
# static-musl link needs no external libs. Pure userspace — no kernel
# UAPI surface beyond standard libc, so no uapi-stage headers are needed
# (the configure probes link against musl libc only). Static link so the
# binary works pre-dynamic-linker.
#
# -std=gnu11 is mandatory: GCC 14/15 default to C23, where an empty
# parameter list `()` means `(void)`. The bundled oniguruma (st.c,
# regparse.c) declares K&R-style unprototyped function pointers and calls
# them with args — a hard error under C23 ("too many arguments" /
# incompatible-pointer-types). gnu11 restores the loose `()` semantics.
# jq proper needs C99+ (decl-in-for), so plain -std=gnu89 (the bash
# recipe's choice) is too old here; gnu11 satisfies both.
set -e

cd "$(dirname "$0")"
SRC="jq-1.7.1"

if [ ! -d "$SRC" ]; then
  echo "missing $SRC — run tools/fetch-jq.sh first" >&2
  exit 1
fi

CROSS_ROOT="$(cd ../cross/aarch64-linux-musl-cross && pwd)"
CROSS_CC="$CROSS_ROOT/bin/aarch64-linux-musl-gcc"
CROSS_STRIP="$CROSS_ROOT/bin/aarch64-linux-musl-strip"

cleanup_objs() {
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  rm -f "$SRC/config.cache"
}

# jq's configure runs a few link/run probes that fail under a cross host
# (it can't execute the aarch64 a.out). Seed the answers that the
# bundled oniguruma + jq need so configure doesn't guess wrong. These
# are the standard glibc/musl-true answers.
config_cache() {
  cat > config.cache <<'EOF'
ac_cv_func_memmem=yes
ac_cv_func_strptime=yes
ac_cv_func_timegm=yes
ac_cv_func_gmtime_r=yes
ac_cv_func_localtime_r=yes
ac_cv_func_isatty=yes
ac_cv_func_mkstemp=yes
ac_cv_func_setenv=yes
ac_cv_func_strftime=yes
ac_cv_func__setjmp=yes
EOF
}

build_one() {
  arch="$1"; cc="$2"; strip_tool="$3"; suffix="$4"
  echo "=== building jq for $arch ==="
  cleanup_objs
  config_cache
  cp config.cache "$SRC/config.cache"
  ( cd "$SRC" && \
    CC="$cc" \
    CFLAGS="-Os -static -std=gnu11 -Wno-incompatible-pointer-types -Wno-implicit-function-declaration" \
    LDFLAGS="-static" \
    ./configure \
      --host="${arch}-linux-musl" \
      --cache-file=config.cache \
      --disable-shared \
      --enable-static \
      --enable-all-static \
      --with-oniguruma=builtin \
      --disable-maintainer-mode \
      --disable-docs \
      --prefix=/usr \
    && make -j4 \
  )
  cp "$SRC/jq" "jq-$suffix"
  "$strip_tool" "jq-$suffix" 2>/dev/null || true
  echo "  → jq-$suffix  ($(stat -c %s "jq-$suffix") bytes)"
}

build_one "x86_64"  "musl-gcc"   "strip"          "x86_64"
build_one "aarch64" "$CROSS_CC"  "$CROSS_STRIP"   "aarch64"

echo "OK — built jq for {x86_64, aarch64}"
