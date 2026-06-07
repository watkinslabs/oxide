#!/usr/bin/env bash
# Fetch + verify dua-cli source tarball. Extracts under vendor/dua/.
# Idempotent. Built static-musl per-arch by vendor/dua/build.sh.
set -euo pipefail
VERSION="2.30.1"
SHA256="e7cb52b4dc6bf89a554b0f1292344eafceeace1cbf957a2c0942bf1201b404a9"
URL="https://github.com/Byron/dua-cli/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/dua"
SRCDIR="${VDIR}/dua-cli-${VERSION}"
TARBALL="${VDIR}/dua-cli-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "dua-cli-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
