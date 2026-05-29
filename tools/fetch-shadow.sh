#!/usr/bin/env bash
# Fetch shadow-utils. D2 of the distro roadmap.
set -euo pipefail

VERSION="4.16.0"
SHA256="b78e3921a95d53282a38e90628880624736bf6235e36eea50c50835f59a3530b"
URL="https://github.com/shadow-maint/shadow/releases/download/${VERSION}/shadow-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/shadow"
SRCDIR="${VDIR}/shadow-${VERSION}"
TARBALL="${VDIR}/shadow-${VERSION}.tar.xz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then
    echo "shadow-${VERSION} already extracted"
    exit 0
fi
if [ ! -f "${TARBALL}" ]; then
    curl -fL -o "${TARBALL}" "${URL}"
fi
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch -- got ${actual}" >&2
    exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
