#!/usr/bin/env bash
# Fetch + verify libxcrypt source tarball. Track L2: real crypt() for shadow.
set -euo pipefail
VERSION="4.4.36"
SHA256="e5e1f4caee0a01de2aee26e3138807d6d3ca2b8e67287966d1fefd65e1fd8943"
URL="https://github.com/besser82/libxcrypt/releases/download/v${VERSION}/libxcrypt-${VERSION}.tar.xz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libxcrypt"; SRCDIR="${VDIR}/libxcrypt-${VERSION}"; TARBALL="${VDIR}/libxcrypt-${VERSION}.tar.xz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libxcrypt-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xf "${TARBALL}" -C "${VDIR}"
echo "libxcrypt-${VERSION} ready; run vendor/libxcrypt/build.sh"
