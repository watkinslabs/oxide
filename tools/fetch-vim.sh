#!/usr/bin/env bash
# Fetch + verify vim source tarball. Extracts under vendor/vim/.
# Idempotent: skips download/extract if target tree already exists.
#
# F251: vendor vim for the distro buildout per CLAUDE.md§Discipline
# (distro endgame is GNOME/Wayland; vim is the canonical editor
# slot). Cross-builds against the static-musl ncurses staged at
# vendor/ncurses/install-<arch>/ (F250).
set -euo pipefail

VERSION="9.1.0950"
SHA256="ff31083fdbdde49a1cd6e95ac751f194d75065d79c8d07d138a9c1afe3494b31"
URL="https://github.com/vim/vim/archive/refs/tags/v${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/vim"
SRCDIR="${VDIR}/vim-${VERSION}"
TARBALL="${VDIR}/vim-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "vim-${VERSION} already extracted at ${SRCDIR}"
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
