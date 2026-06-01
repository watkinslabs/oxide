#!/usr/bin/env bash
# Fetch + verify expat source tarball. Track L2: dbus XML parser dep.
set -euo pipefail
VERSION="2.6.2"; TAG="R_2_6_2"
SHA256="d4cf38d26e21a56654ffe4acd9cd5481164619626802328506a2869afab29ab3"
URL="https://github.com/libexpat/libexpat/releases/download/${TAG}/expat-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/expat"; SRCDIR="${VDIR}/expat-${VERSION}"; TARBALL="${VDIR}/expat-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "expat-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "expat-${VERSION} ready; run vendor/expat/build.sh"
