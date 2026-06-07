#!/usr/bin/env bash
# Fetch + verify ncdu source tarball. Extracts under vendor/ncdu/.
# Idempotent: skips download/extract if target tree already exists.
#
# ncdu (NCurses Disk Usage) — disk-usage TUI. Vendored as static-musl C
# linked against the already-vendored ncurses (libncursesw.a). Use the
# 1.x C line ONLY — the 2.x line is rewritten in Zig and is out of scope
# for the C cross-build pathway.
set -euo pipefail

VERSION="1.21"
SHA256="a894d3a9b46bce578a6039bef48f54533ec402fb589b0769bfbb1d1edf9601a6"
URL="https://dev.yorhel.nl/download/ncdu-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/ncdu"
SRCDIR="${VDIR}/ncdu-${VERSION}"
TARBALL="${VDIR}/ncdu-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "ncdu-${VERSION} already extracted at ${SRCDIR}"
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
