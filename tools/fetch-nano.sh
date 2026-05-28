#!/usr/bin/env bash
# Fetch + verify GNU nano source tarball.
# F255: distro pick after vim/less for the casual-editor slot.
set -euo pipefail

VERSION="8.5"
SHA256="000b011d339c141af9646d43288f54325ff5c6e8d39d6e482b787bbc6654c26a"
URL="https://www.nano-editor.org/dist/v8/nano-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/nano"
SRCDIR="${VDIR}/nano-${VERSION}"
TARBALL="${VDIR}/nano-${VERSION}.tar.xz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then
    echo "nano-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi
if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
fi
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch -- got ${actual}." >&2
    exit 1
fi
echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
