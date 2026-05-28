#!/usr/bin/env bash
# Fetch + verify GNU tar source tarball.
# F220: fifth GNU userspace program after bash/sed/coreutils/grep.
set -euo pipefail

VERSION="1.35"
SHA256="4d62ff37342ec7aed748535323930c7cf94acf71c3591882b26a7ea50f3edc16"
URL="https://ftp.gnu.org/gnu/tar/tar-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/tar"
SRCDIR="${VDIR}/tar-${VERSION}"
TARBALL="${VDIR}/tar-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "tar-${VERSION} already extracted at ${SRCDIR}"
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
