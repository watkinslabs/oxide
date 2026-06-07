#!/usr/bin/env bash
# Fetch + verify the gron source tarball. Extracts under vendor/gron/.
# Idempotent. gron is a Go program (makes JSON greppable) — built static
# (CGO_ENABLED=0) per arch by vendor/gron/build.sh using the vendored Go
# SDK (vendor/go). github.com/tomnomnom/gron.
set -euo pipefail
VERSION="0.7.1"
SHA256="1c98f2ef2ba03558864b1ab5e9c4b47a2e89d3ffaf24cfa0ac75cd38d775feb4"
URL="https://github.com/tomnomnom/gron/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/gron"
SRCDIR="${VDIR}/gron-${VERSION}"
TARBALL="${VDIR}/gron-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "gron-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
  exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
