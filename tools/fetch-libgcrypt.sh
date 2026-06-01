#!/usr/bin/env bash
# Fetch + verify libgcrypt source. Track L2: systemd unconditional DEPENDS.
set -euo pipefail
VERSION="1.10.3"
SHA256="8b0870897ac5ac67ded568dcfadf45969cfa8a6beb0fd60af2a9eadc2a3272aa"
URL="https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${VERSION}.tar.bz2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libgcrypt"; SRCDIR="${VDIR}/libgcrypt-${VERSION}"; TARBALL="${VDIR}/libgcrypt-${VERSION}.tar.bz2"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libgcrypt-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xjf "${TARBALL}" -C "${VDIR}"
echo "libgcrypt-${VERSION} ready; run vendor/libgcrypt/build.sh (needs libgpg-error fetched)"
