#!/usr/bin/env bash
# Fetch + verify zstd source tarball. Track L2 systemd dep (journal compression).
set -euo pipefail
VERSION="1.5.6"
SHA256="8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1"
URL="https://github.com/facebook/zstd/releases/download/v${VERSION}/zstd-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/zstd"; SRCDIR="${VDIR}/zstd-${VERSION}"; TARBALL="${VDIR}/zstd-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "zstd-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "zstd-${VERSION} ready; run vendor/zstd/build.sh"
