#!/usr/bin/env bash
# Fetch + verify GNU grep source tarball.
# F219: fourth GNU userspace program after bash/sed/coreutils.
set -euo pipefail

VERSION="3.11"
SHA256="1db2aedde89d0dea42b16d9528f894c8d15dae4e190b59aecc78f5a951276eab"
URL="https://ftp.gnu.org/gnu/grep/grep-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/grep"
SRCDIR="${VDIR}/grep-${VERSION}"
TARBALL="${VDIR}/grep-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "grep-${VERSION} already extracted at ${SRCDIR}"
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
