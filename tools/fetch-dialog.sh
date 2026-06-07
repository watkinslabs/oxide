#!/usr/bin/env bash
# Fetch + verify dialog source tarball. Extracts under vendor/dialog/.
# Idempotent: skips download/extract if target tree already exists.
#
# dialog (invisible-island.net/dialog) — the classic curses TUI widget
# tool (msgbox/menu/inputbox/...). Vendored as static-musl C linked
# against the already-vendored ncurses (libncursesw.a). Pins
# 1.3-20240619; if upstream has rotated that exact release off the
# archives page (404), falls back to the newest 1.3-* tarball published.
set -euo pipefail

VERSION="1.3-20240619"
SHA256="5d8c4318963db3fd383525340276e0e05ee3dea9a6686c20779f5433b199547d"
URL="https://invisible-island.net/archives/dialog/dialog-${VERSION}.tgz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/dialog"

mkdir -p "${VDIR}"

# Resolve a working version: try the pinned one, else newest 1.3-* on the
# archives index.
resolve_version() {
    if curl -fsIL "https://invisible-island.net/archives/dialog/dialog-${VERSION}.tgz" >/dev/null 2>&1; then
        return 0
    fi
    echo "dialog-${VERSION} not found on archives — probing newest 1.3-*" >&2
    latest="$(curl -fsL "https://invisible-island.net/archives/dialog/" \
        | grep -oE 'dialog-1\.3-[0-9]+\.tgz' | sort -V | tail -1)"
    if [ -z "${latest}" ]; then
        echo "could not resolve any dialog-1.3-* tarball" >&2
        exit 1
    fi
    VERSION="$(echo "${latest}" | sed -E 's/dialog-(1\.3-[0-9]+)\.tgz/\1/')"
    URL="https://invisible-island.net/archives/dialog/dialog-${VERSION}.tgz"
    SHA256=""   # unknown for a fallback release; computed + reported below
    echo "falling back to dialog-${VERSION}" >&2
}

resolve_version

SRCDIR="${VDIR}/dialog-${VERSION}"
TARBALL="${VDIR}/dialog-${VERSION}.tgz"

if [ -d "${SRCDIR}" ]; then
    echo "dialog-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
fi

actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
if [ -n "${SHA256}" ]; then
    echo "verifying sha256"
    if [ "${actual}" != "${SHA256}" ]; then
        echo "sha256 mismatch — upstream may have re-released." >&2
        echo "  expected ${SHA256}" >&2
        echo "  got      ${actual}" >&2
        echo "If you trust the new checksum, update SHA256 in this script." >&2
        exit 1
    fi
else
    echo "fallback release sha256: ${actual}" >&2
    echo "  pin this in SHA256 once verified." >&2
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
