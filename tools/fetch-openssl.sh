#!/usr/bin/env bash
# Fetch + verify openssl source. Track L2: systemd resolved DoT/DNSSEC + journal TLS.
set -euo pipefail
VERSION="3.0.15"
SHA256="23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533"
URL="https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/openssl-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/openssl"; SRCDIR="${VDIR}/openssl-${VERSION}"; TARBALL="${VDIR}/openssl-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "openssl-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 20 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "openssl-${VERSION} ready; run vendor/openssl/build.sh"
