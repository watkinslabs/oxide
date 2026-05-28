#!/usr/bin/env bash
# Fetch + verify GNU sed source tarball.
# F217: GNU sed cross-built as the next distro-pathway package after
# bash. Exercises gnulib's regex engine + getopt + libsigsegv, which
# in turn lean on a wide POSIX surface (sigaction handlers, mmap
# guard pages, alarm, etc.) — every gap surfaces a kernel/libc fix.
set -euo pipefail

VERSION="4.9"
SHA256="6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181"
URL="https://ftp.gnu.org/gnu/sed/sed-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/sed"
SRCDIR="${VDIR}/sed-${VERSION}"
TARBALL="${VDIR}/sed-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "sed-${VERSION} already extracted at ${SRCDIR}"
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
