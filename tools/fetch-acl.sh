#!/usr/bin/env bash
# Fetch + verify acl source. Track L2: systemd journal file ACLs (libacl).
set -euo pipefail
VERSION="2.3.2"
SHA256="5f2bdbad629707aa7d85c623f994aa8a1d2dec55a73de5205bac0bf6058a2f7c"
URL="https://download.savannah.nongnu.org/releases/acl/acl-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/acl"; SRCDIR="${VDIR}/acl-${VERSION}"; TARBALL="${VDIR}/acl-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "acl-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "acl-${VERSION} ready; run vendor/acl/build.sh (needs attr built first)"
