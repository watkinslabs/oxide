#!/usr/bin/env bash
# Fetch + verify the lazygit source tarball. Extracts under vendor/lazygit/.
# Idempotent. lazygit is a Go program — built static (CGO_ENABLED=0) per
# arch by vendor/lazygit/build.sh using the vendored Go SDK (vendor/go).
set -euo pipefail
VERSION="0.44.1"
SHA256="02b67d38e07ae89b0ddd3b4917bd0cfcdfb5e158ed771566d3eb81f97f78cc26"
URL="https://github.com/jesseduffield/lazygit/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/lazygit"
SRCDIR="${VDIR}/lazygit-${VERSION}"
TARBALL="${VDIR}/lazygit-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "lazygit-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
  exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
