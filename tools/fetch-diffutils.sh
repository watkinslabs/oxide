#!/usr/bin/env bash
# Fetch + verify GNU diffutils source tarball.
# F224: ninth GNU userspace program.
set -euo pipefail

VERSION="3.10"
SHA256="90e5e93cc724e4ebe12ede80df1634063c7a855692685919bfe60b556c9bd09e"
URL="https://ftp.gnu.org/gnu/diffutils/diffutils-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/diffutils"
SRCDIR="${VDIR}/diffutils-${VERSION}"
TARBALL="${VDIR}/diffutils-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "diffutils-${VERSION} already extracted at ${SRCDIR}"
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
