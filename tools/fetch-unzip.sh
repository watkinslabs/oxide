#!/usr/bin/env bash
# Fetch + verify Info-ZIP UnZip 6.0 source. Real upstream zip extractor
# (the `unzip` distros ship). Hand-rolled unix/Makefile — cross-builds via
# the `generic` target (no configure run-test), per-arch CC, static.
set -euo pipefail

VERSION="60"
SHA256="036d96991646d0449ed0aa952e4fbe21b476ce994abc276e49d30e686708bd37"
URL="https://downloads.sourceforge.net/infozip/unzip${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/unzip"
SRCDIR="${VDIR}/unzip${VERSION}"
TARBALL="${VDIR}/unzip${VERSION}.tar.gz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "unzip${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; fi
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch — got ${actual}." >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
