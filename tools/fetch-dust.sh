#!/usr/bin/env bash
# Fetch + verify dust source tarball. Extracts under vendor/dust/.
# Idempotent. Built static-musl per-arch by vendor/dust/build.sh.
set -euo pipefail
VERSION="1.1.1"
SHA256="98cae3e4b32514e51fcc1ed07fdbe6929d4b80942925348cc6e57b308d9c4cb0"
URL="https://github.com/bootandy/dust/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/dust"
SRCDIR="${VDIR}/dust-${VERSION}"
TARBALL="${VDIR}/dust-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "dust-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
