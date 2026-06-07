#!/usr/bin/env bash
# Fetch + verify yazi source tarball. Extracts under vendor/yazi/.
# Idempotent. Built static-musl per-arch by vendor/yazi/build.sh.
set -euo pipefail
VERSION="0.4.2"
SHA256="88995c90954d140f455cf9ca4f87f9ca36390717377be86b0672456e1eb5f65f"
URL="https://github.com/sxyazi/yazi/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/yazi"
SRCDIR="${VDIR}/yazi-${VERSION}"
TARBALL="${VDIR}/yazi-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "yazi-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
