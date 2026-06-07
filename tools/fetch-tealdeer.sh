#!/usr/bin/env bash
# Fetch + verify tealdeer source tarball. Extracts under vendor/tealdeer/.
# Idempotent. Built static-musl per-arch by vendor/tealdeer/build.sh.
set -euo pipefail
VERSION="1.7.1"
TAG="v${VERSION}"
SHA256="2b10e141774d2a50d25a1d3ca3d911dedc0e1313366ce0a364068c7a686300d8"
URL="https://github.com/tealdeer-rs/tealdeer/archive/refs/tags/${TAG}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/tealdeer"
SRCDIR="${VDIR}/tealdeer-${VERSION}"
TARBALL="${VDIR}/tealdeer-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "tealdeer-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
