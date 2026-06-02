#!/usr/bin/env bash
# Fetch + verify libffi source. Roadmap item 4: CPython _ctypes (ffi.h).
set -euo pipefail
VERSION="3.4.6"
SHA256="b0dea9df23c863a7a50e825440f3ebffabd65df1497108e5d437747843895a4e"
URL="https://github.com/libffi/libffi/releases/download/v${VERSION}/libffi-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libffi"; SRCDIR="${VDIR}/libffi-${VERSION}"; TARBALL="${VDIR}/libffi-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libffi-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 20 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "libffi-${VERSION} ready; run vendor/libffi/build.sh"
