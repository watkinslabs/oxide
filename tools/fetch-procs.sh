#!/usr/bin/env bash
# Fetch + verify procs source tarball. Extracts under vendor/procs/.
# Idempotent. Built static-musl per-arch by vendor/procs/build.sh.
set -euo pipefail
VERSION="0.14.10"
SHA256="7b287ac253fd1d202b0ea6a9a8ba2ed97598cf8e7dfd539bd40e382c6dc6d350"
URL="https://github.com/dalance/procs/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/procs"
SRCDIR="${VDIR}/procs-${VERSION}"
TARBALL="${VDIR}/procs-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "procs-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
