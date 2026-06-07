#!/usr/bin/env bash
# Fetch + verify bat source tarball. Extracts under vendor/bat/.
# Idempotent. Built static-musl per-arch by vendor/bat/build.sh.
set -euo pipefail
VERSION="0.24.0"
SHA256="907554a9eff239f256ee8fe05a922aad84febe4fe10a499def72a4557e9eedfb"
URL="https://github.com/sharkdp/bat/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/bat"
SRCDIR="${VDIR}/bat-${VERSION}"
TARBALL="${VDIR}/bat-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "bat-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
