#!/usr/bin/env bash
# Fetch + verify eza source tarball. Extracts under vendor/eza/.
# Idempotent. Built static-musl per-arch by vendor/eza/build.sh.
set -euo pipefail
VERSION="0.20.24"
SHA256="e5a1761f05adc74b80d59036819e768060971c6f5107e208024c752a2af02ccc"
URL="https://github.com/eza-community/eza/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/eza"
SRCDIR="${VDIR}/eza-${VERSION}"
TARBALL="${VDIR}/eza-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "eza-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
