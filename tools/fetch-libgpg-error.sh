#!/usr/bin/env bash
# Fetch + verify libgpg-error source. Track L2: libgcrypt's dep.
set -euo pipefail
VERSION="1.50"
SHA256="69405349e0a633e444a28c5b35ce8f14484684518a508dc48a089992fe93e20a"
URL="https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${VERSION}.tar.bz2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libgpg-error"; SRCDIR="${VDIR}/libgpg-error-${VERSION}"; TARBALL="${VDIR}/libgpg-error-${VERSION}.tar.bz2"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libgpg-error-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xjf "${TARBALL}" -C "${VDIR}"
echo "libgpg-error-${VERSION} ready; run vendor/libgpg-error/build.sh"
