#!/usr/bin/env bash
# Fetch + verify bottom (btm) source tarball. Extracts under vendor/bottom/.
# Idempotent. Built static-musl per-arch by vendor/bottom/build.sh.
# NB: bottom release tags have NO leading "v" (e.g. 0.10.2).
set -euo pipefail
VERSION="0.10.2"
SHA256="1db45fe9bc1fabb62d67bf8a1ea50c96e78ff4d2a5e25bf8ae8880e3ad5af80a"
URL="https://github.com/ClementTsang/bottom/archive/refs/tags/${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/bottom"
SRCDIR="${VDIR}/bottom-${VERSION}"
TARBALL="${VDIR}/bottom-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "bottom-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
