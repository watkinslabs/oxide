#!/usr/bin/env bash
# Fetch + verify Info-ZIP Zip 3.0 source — the `zip` compressor (companion to
# UnZip 6.0). Hand-rolled unix/Makefile; cross-builds via the `generic_gcc`/
# predefined target (no configure run-test), per-arch CC, static.
set -euo pipefail

VERSION="30"
SHA256="f0e8bb1f9b7eb0b01285495a2699df3a4b766784c1765a8f1aeedf63c0806369"
URL="https://downloads.sourceforge.net/infozip/zip${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/zip"
SRCDIR="${VDIR}/zip${VERSION}"
TARBALL="${VDIR}/zip${VERSION}.tar.gz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "zip${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; fi
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch — got ${actual}." >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
