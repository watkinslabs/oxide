#!/usr/bin/env bash
# Fetch + verify ncurses source tarball. Extracts under vendor/ncurses/.
# Idempotent: skips download/extract if target tree already exists.
#
# F250: ncurses static-musl prerequisite for vim cross-build (T17).
# Vim 9.1 dropped the builtin termcap fallback so it now requires
# linking against tinfo/ncurses/termlib/termcap. We ship ncurses
# at vendor/ncurses/install-<arch>/ for downstream tool builds.
set -euo pipefail

VERSION="6.5"
SHA256="136d91bc269a9a5785e5f9e980bc76ab57428f604ce3e5a5a90cebc767971cc6"
URL="https://invisible-mirror.net/archives/ncurses/ncurses-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/ncurses"
SRCDIR="${VDIR}/ncurses-${VERSION}"
TARBALL="${VDIR}/ncurses-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "ncurses-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
fi

echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch -- upstream may have re-released. Got ${actual}." >&2
    echo "If you trust the new checksum, update SHA256 in this script." >&2
    exit 1
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
