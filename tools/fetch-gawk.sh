#!/usr/bin/env bash
# Fetch + verify GNU gawk source tarball.
# F222: seventh GNU userspace program (bash/sed/coreutils/grep/tar/make/awk).
set -euo pipefail

VERSION="5.3.1"
SHA256="694db764812a6236423d4ff40ceb7b6c4c441301b72ad502bb5c27e00cd56f78"
URL="https://ftp.gnu.org/gnu/gawk/gawk-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/gawk"
SRCDIR="${VDIR}/gawk-${VERSION}"
TARBALL="${VDIR}/gawk-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "gawk-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
fi

echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch — upstream may have re-released. Got ${actual}." >&2
    exit 1
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
