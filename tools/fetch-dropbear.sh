#!/usr/bin/env bash
# Fetch + verify dropbear source tarball. Extracts under vendor/dropbear/.
# Idempotent: skips download/extract if target tree already exists.
set -euo pipefail

VERSION="2024.86"
SHA256="e78936dffc395f2e0db099321d6be659190966b99712b55c530dd0a1822e0a5e"
URL="https://matt.ucc.asn.au/dropbear/releases/dropbear-${VERSION}.tar.bz2"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/dropbear"
SRCDIR="${VDIR}/dropbear-${VERSION}"
TARBALL="${VDIR}/dropbear-${VERSION}.tar.bz2"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "dropbear-${VERSION} already extracted at ${SRCDIR}"
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
    echo "If you trust the new checksum, update SHA256 in this script." >&2
    exit 1
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
