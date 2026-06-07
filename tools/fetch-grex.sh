#!/usr/bin/env bash
# Fetch + verify grex source tarball. Extracts under vendor/grex/.
# Idempotent. Built static-musl per-arch by vendor/grex/build.sh.
set -euo pipefail
VERSION="1.4.5"
SHA256="4e849b29b387afc583856f24923b76052ad90e320c2caacfc6452e6d9deb6b14"
URL="https://github.com/pemistahl/grex/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/grex"
SRCDIR="${VDIR}/grex-${VERSION}"
TARBALL="${VDIR}/grex-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "grex-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
