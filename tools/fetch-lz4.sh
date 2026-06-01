#!/usr/bin/env bash
# Fetch + verify lz4 source tarball. Track L2 systemd dep.
set -euo pipefail
VERSION="1.9.4"
SHA256="0b0e3aa07c8c063ddf40b082bdf7e37a1562bda40a0ff5272957f3e987e0e54b"
URL="https://github.com/lz4/lz4/releases/download/v${VERSION}/lz4-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/lz4"; SRCDIR="${VDIR}/lz4-${VERSION}"; TARBALL="${VDIR}/lz4-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "lz4-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "lz4-${VERSION} ready; run vendor/lz4/build.sh"
