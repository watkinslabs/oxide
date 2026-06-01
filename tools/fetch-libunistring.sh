#!/usr/bin/env bash
# Fetch + verify libunistring source. Track L2: libidn2's dep.
set -euo pipefail
VERSION="1.2"
SHA256="fd6d5662fa706487c48349a758b57bc149ce94ec6c30624ec9fdc473ceabbc8e"
URL="https://ftp.gnu.org/gnu/libunistring/libunistring-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libunistring"; SRCDIR="${VDIR}/libunistring-${VERSION}"; TARBALL="${VDIR}/libunistring-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libunistring-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 20 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "libunistring-${VERSION} ready; run vendor/libunistring/build.sh"
