#!/usr/bin/env bash
# Fetch + verify dhcpcd source tarball. Extracts under vendor/dhcpcd/.
# Idempotent: skips download/extract if target tree already exists.
set -euo pipefail

VERSION="10.3.2"
SHA256="b6aa46932074906a9badef1bfe142b8aff9d041c2689e1ef8b74c12e9fd942bd"
URL="https://github.com/NetworkConfiguration/dhcpcd/releases/download/v${VERSION}/dhcpcd-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/dhcpcd"
SRCDIR="${VDIR}/dhcpcd-${VERSION}"
TARBALL="${VDIR}/dhcpcd-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "dhcpcd-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
fi

echo "verifying sha256"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
