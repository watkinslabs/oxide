#!/usr/bin/sh
# acl 2.3.2 SHARED build — per-arch libacl.so under
# vendor/acl/install-<arch>/{lib,include}.
# Track L2: systemd journal file ACLs (libacl). DT_NEEDEDs libattr (F343).
set -e
cd "$(dirname "$0")"
SRC="acl-2.3.2"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-acl.sh first" >&2; exit 1; }
CROSS="$(cd ../cross/aarch64-linux-musl-cross/bin && pwd)"
ATTR_ROOT="$(cd ../attr && pwd)"
COMMON="--enable-shared --disable-static --disable-nls --disable-rpath"

build_one() {
  arch="$1"; cc="$2"; host="$3"
  install="install-${arch}"
  attr_inc="${ATTR_ROOT}/install-${arch}/include"
  attr_lib="${ATTR_ROOT}/install-${arch}/lib"
  [ -f "${attr_lib}/libattr.so" ] || { echo "missing attr for $arch — run vendor/attr/build.sh first" >&2; exit 1; }
  echo "=== building libacl.so for $arch ==="
  rm -rf "$install"; mkdir -p "$install/lib" "$install/include/acl" "$install/include/sys"
  ( cd "$SRC" && make distclean >/dev/null 2>&1 || true )
  extra=""
  [ "$arch" = "x86_64" ] && extra="-idirafter /usr/include"
  # Non-recursive automake: build just the library target. The CLI tools
  # (getfacl/setfacl/chacl) use GNU basename() which musl lacks; we ship
  # only libacl.so. rpath-link so the strict arm ld resolves libacl.so's
  # transitive libattr.so dependency at link time.
  ( cd "$SRC" && CC="$cc" \
      CFLAGS="-O2 -fPIC $extra -I${attr_inc}" \
      LDFLAGS="-L${attr_lib} -Wl,-rpath-link,${attr_lib}" \
      ./configure $host $COMMON >/dev/null \
      && make -j4 libmisc.la libacl.la >/dev/null )
  real="$(cd "$SRC/.libs" && ls libacl.so.1.* 2>/dev/null | grep -v '\.la$' | head -1)"
  [ -n "$real" ] || { echo "no libacl.so built for $arch" >&2; exit 1; }
  cp -L "$SRC/.libs/$real" "$install/lib/$real"
  ( cd "$install/lib" && ln -sf "$real" libacl.so.1 && ln -sf libacl.so.1 libacl.so )
  cp "$SRC"/include/*.h "$install/include/acl/" 2>/dev/null || true
  cp "$SRC"/include/acl.h "$install/include/sys/" 2>/dev/null || true
  echo "  → $install/lib/$real ($(stat -c %s "$install/lib/$real") bytes)"
}

build_one "x86_64"  "musl-gcc" ""
build_one "aarch64" "$CROSS/aarch64-linux-musl-gcc" "--host=aarch64-linux-musl"
