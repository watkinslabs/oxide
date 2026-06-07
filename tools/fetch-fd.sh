#!/usr/bin/env bash
# Fetch + verify fd source tarball. Extracts under vendor/fd/.
# Idempotent. Built static-musl per-arch by vendor/fd/build.sh.
set -euo pipefail
VERSION="10.2.0"
SHA256="73329fe24c53f0ca47cd0939256ca5c4644742cb7c14cf4114c8c9871336d342"
URL="https://github.com/sharkdp/fd/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/fd"
SRCDIR="${VDIR}/fd-${VERSION}"
TARBALL="${VDIR}/fd-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "fd-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
