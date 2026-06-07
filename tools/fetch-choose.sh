#!/usr/bin/env bash
# Fetch + verify choose source tarball. Extracts under vendor/choose/.
# Idempotent. Built static-musl per-arch by vendor/choose/build.sh.
set -euo pipefail
VERSION="1.3.6"
SHA256="3d28dc39339dbf5c6197eb803b199661d6d261bc827c194b31b19d1afad01487"
URL="https://github.com/theryangeary/choose/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/choose"
SRCDIR="${VDIR}/choose-${VERSION}"
TARBALL="${VDIR}/choose-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "choose-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
