#!/usr/bin/env bash
# Fetch + verify pcre2 source tarball. Track L2 systemd dep (journal regex).
set -euo pipefail
VERSION="10.44"
SHA256="86b9cb0aa3bcb7994faa88018292bc704cdbb708e785f7c74352ff6ea7d3175b"
URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${VERSION}/pcre2-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/pcre2"; SRCDIR="${VDIR}/pcre2-${VERSION}"; TARBALL="${VDIR}/pcre2-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "pcre2-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "pcre2-${VERSION} ready; run vendor/pcre2/build.sh"
