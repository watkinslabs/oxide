#!/usr/bin/env bash
# Fetch + verify starship source tarball. Extracts under vendor/starship/.
# Idempotent. Built static-musl per-arch by vendor/starship/build.sh.
set -euo pipefail
VERSION="1.21.1"
SHA256="f543dfa3229441ca2a55b8a625ce4bad5756a896378b019f4d0f0e00cf34dcc8"
URL="https://github.com/starship/starship/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/starship"
SRCDIR="${VDIR}/starship-${VERSION}"
TARBALL="${VDIR}/starship-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "starship-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
