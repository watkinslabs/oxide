#!/usr/bin/env bash
# Fetch + verify GNU coreutils source tarball.
# F218: pinned to 8.32 because gnulib in 9.x is heavy on glibc-only
# extensions (mbszero/mcel/c32tolower) that musl lacks. 8.32 builds
# cleanly with the small -D shim in vendor/coreutils/build.sh and
# delivers ~100 working applets.
set -euo pipefail

VERSION="8.32"
SHA256="4458d8de7849df44ccab15e16b1548b285224dbba5f08fac070c1c0e0bcc4cfa"
URL="https://ftp.gnu.org/gnu/coreutils/coreutils-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/coreutils"
SRCDIR="${VDIR}/coreutils-${VERSION}"
TARBALL="${VDIR}/coreutils-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "coreutils-${VERSION} already extracted at ${SRCDIR}"
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
