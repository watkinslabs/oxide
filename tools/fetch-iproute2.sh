#!/usr/bin/env bash
# Fetch iproute2. D4 of the distro roadmap.
set -euo pipefail

VERSION="6.10.0"
SHA256="91a62f82737b44905a00fa803369c447d549e914e9a2a4018fdd75b1d54e8dce"
URL="https://www.kernel.org/pub/linux/utils/net/iproute2/iproute2-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/iproute2"
SRCDIR="${VDIR}/iproute2-${VERSION}"
TARBALL="${VDIR}/iproute2-${VERSION}.tar.xz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "iproute2-${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then curl -fL -o "${TARBALL}" "${URL}"; fi
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch -- got ${actual}" >&2
    exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
