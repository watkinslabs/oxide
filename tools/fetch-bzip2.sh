#!/usr/bin/env bash
# Fetch + verify bzip2 source tarball.
# F226: eleventh userspace program (after bash/sed/coreutils/grep/
# tar/make/awk/findutils/diffutils/patch). bzip2 has a hand-rolled
# Makefile (no autoconf), so the cross-build is just per-arch CC.
set -euo pipefail

VERSION="1.0.8"
SHA256="ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269"
URL="https://sourceware.org/pub/bzip2/bzip2-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/bzip2"
SRCDIR="${VDIR}/bzip2-${VERSION}"
TARBALL="${VDIR}/bzip2-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "bzip2-${VERSION} already extracted at ${SRCDIR}"
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
