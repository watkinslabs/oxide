#!/usr/bin/env bash
# Fetch + verify the glow source tarball. Extracts under vendor/glow/.
# Idempotent. glow (charmbracelet/glow) is a Go markdown renderer —
# built static (CGO_ENABLED=0) per arch by vendor/glow/build.sh using
# the vendored Go SDK (vendor/go). If the pinned v2.x tag 404s, bump
# VERSION to the latest v2.x release.
set -euo pipefail
VERSION="2.0.0"
SHA256="55872e36c006e7e715b86283baf14add1f85b0a0304e867dd0d80e8d7afe49a8"
URL="https://github.com/charmbracelet/glow/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/glow"
SRCDIR="${VDIR}/glow-${VERSION}"
TARBALL="${VDIR}/glow-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "glow-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
  exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
