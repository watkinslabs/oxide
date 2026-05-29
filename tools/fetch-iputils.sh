#!/usr/bin/env bash
# Fetch iputils. D5 of the distro roadmap.
set -euo pipefail

VERSION="20240117"
SHA256="7ed46e876e4157e1d20c40ec945e1ce0f3af3b10b5f6373e423135c6f22cd116"
URL="https://github.com/iputils/iputils/releases/download/${VERSION}/iputils-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/iputils"
SRCDIR="${VDIR}/iputils-${VERSION}"
TARBALL="${VDIR}/iputils-${VERSION}.tar.gz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "iputils-${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then curl -fL -o "${TARBALL}" "${URL}"; fi
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch -- got ${actual}" >&2
    exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
