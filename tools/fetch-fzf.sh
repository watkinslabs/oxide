#!/usr/bin/env bash
# Fetch + verify the fzf source tarball. Extracts under vendor/fzf/.
# Idempotent. fzf is a Go program — built static (CGO_ENABLED=0) per
# arch by vendor/fzf/build.sh using the vendored Go SDK (vendor/go).
set -euo pipefail
VERSION="0.55.0"
SHA256="805383f71bca7f8fb271ecd716852aea88fd898d5027d58add9e43df6ea766da"
URL="https://github.com/junegunn/fzf/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/fzf"
SRCDIR="${VDIR}/fzf-${VERSION}"
TARBALL="${VDIR}/fzf-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "fzf-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
  exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
