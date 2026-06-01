#!/usr/bin/env bash
# Fetch + verify libidn2 source. Track L2: systemd-resolved IDNA.
set -euo pipefail
VERSION="2.3.7"
SHA256="4c21a791b610b9519b9d0e12b8097bf2f359b12f8dd92647611a929e6bfd7d64"
URL="https://ftp.gnu.org/gnu/libidn/libidn2-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libidn2"; SRCDIR="${VDIR}/libidn2-${VERSION}"; TARBALL="${VDIR}/libidn2-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libidn2-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 20 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "libidn2-${VERSION} ready; run vendor/libunistring/build.sh then vendor/libidn2/build.sh"
