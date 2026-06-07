#!/usr/bin/env bash
# Fetch + verify the micro source tarball. Extracts under vendor/micro/.
# Idempotent. micro is a Go program — built static (CGO_ENABLED=0) per
# arch by vendor/micro/build.sh using the vendored Go SDK (vendor/go).
set -euo pipefail
VERSION="2.0.14"
SHA256="40177579beb3846461036387b649c629395584a4bbe970f61ba7591bd9c0185a"
URL="https://github.com/zyedidia/micro/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/micro"
SRCDIR="${VDIR}/micro-${VERSION}"
TARBALL="${VDIR}/micro-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "micro-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
  exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
