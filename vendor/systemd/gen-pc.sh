#!/usr/bin/sh
# Generate minimal pkg-config .pc files for the staged L2 libs into
# vendor/<v>/install-<arch>/lib/pkgconfig/, so systemd's meson
# dependency() resolves against OUR musl tree (not host glibc libs).
# Track D6. Versions match what systemd's min-version checks expect.
set -e
arch="${1:?usage: gen-pc.sh <x86_64|aarch64>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # vendor/

# emit <vendor> <pcname> <Name> <Version> <-llibs> <Requires>
emit() {
  vend="$1"; pc="$2"; name="$3"; ver="$4"; libs="$5"; reqs="$6"
  pfx="${ROOT}/${vend}/install-${arch}"
  dir="${pfx}/lib/pkgconfig"
  mkdir -p "$dir"
  {
    echo "prefix=${pfx}"
    echo "libdir=\${prefix}/lib"
    echo "includedir=\${prefix}/include"
    echo ""
    echo "Name: ${name}"
    echo "Description: oxide L2 staged ${name}"
    echo "Version: ${ver}"
    [ -n "$reqs" ] && echo "Requires: ${reqs}"
    echo "Libs: -L\${libdir} ${libs}"
    echo "Cflags: -I\${includedir}"
  } > "${dir}/${pc}.pc"
}

emit libcap       libcap        libcap        2.69    "-lcap"        ""
emit libseccomp   libseccomp    libseccomp    2.5.5   "-lseccomp"    ""
emit kmod         libkmod       libkmod       31      "-lkmod"       ""
emit libgpg-error gpg-error     gpg-error     1.50    "-lgpg-error"  ""
emit libgcrypt    libgcrypt     libgcrypt     1.10.3  "-lgcrypt"     "gpg-error"
emit openssl      libcrypto     OpenSSL-libcrypto 3.0.15 "-lcrypto"  ""
emit openssl      libssl        OpenSSL-libssl    3.0.15 "-lssl"     "libcrypto"
emit openssl      openssl       OpenSSL       3.0.15  "-lssl -lcrypto" "libssl libcrypto"
emit util-linux   blkid         blkid         2.40    "-lblkid"      ""
emit util-linux   mount         mount         2.40    "-lmount"      "blkid"
emit util-linux   uuid          uuid          2.40    "-luuid"       ""
emit util-linux   smartcols     smartcols     2.40    "-lsmartcols"  ""
emit acl          libacl        libacl        2.3.2   "-lacl"        ""
emit attr         libattr       libattr       2.5.2   "-lattr"       ""
emit libidn2      libidn2       libidn2       2.3.7   "-lidn2"       ""
emit pcre2        libpcre2-8    libpcre2-8    10.44   "-lpcre2-8"    ""
emit zstd         libzstd       libzstd       1.5.6   "-lzstd"       ""
emit lz4          liblz4        liblz4        1.9.4   "-llz4"        ""
echo "gen-pc: wrote .pc files for ${arch}"
