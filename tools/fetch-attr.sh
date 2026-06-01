#!/usr/bin/env bash
# Fetch + verify attr source. Track L2: acl's dep / xattr handling.
set -euo pipefail
VERSION="2.5.2"
SHA256="39bf67452fa41d0948c2197601053f48b3d78a029389734332a6309a680c6c87"
URL="https://download.savannah.nongnu.org/releases/attr/attr-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/attr"; SRCDIR="${VDIR}/attr-${VERSION}"; TARBALL="${VDIR}/attr-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "attr-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "attr-${VERSION} ready; run vendor/attr/build.sh"
