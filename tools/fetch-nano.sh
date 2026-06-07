#!/usr/bin/env bash
# Fetch + verify GNU nano source tarball. Extracts under vendor/nano/.
# Idempotent: skips download/extract if target tree already exists.
#
# GNU nano — terminal text editor. Vendored as static-musl C linked
# against the already-vendored ncurses (libncursesw.a). Pins 8.2; if
# upstream has rotated that point release off the mirror (404), falls
# back to the newest 8.x tarball still published under dist/v8/.
set -euo pipefail

VERSION="8.2"
SHA256="d5ad07dd862facae03051c54c6535e54c7ed7407318783fcad1ad2d7076fffeb"
URL="https://www.nano-editor.org/dist/v8/nano-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/nano"

mkdir -p "${VDIR}"

# Resolve a working version: try the pinned one, else newest 8.x on mirror.
resolve_version() {
    if curl -fsIL "https://www.nano-editor.org/dist/v8/nano-${VERSION}.tar.xz" >/dev/null 2>&1; then
        return 0
    fi
    echo "nano-${VERSION} not found on mirror — probing newest 8.x" >&2
    latest="$(curl -fsL "https://www.nano-editor.org/dist/v8/" \
        | grep -oE 'nano-8\.[0-9]+\.tar\.xz' | sort -V | tail -1)"
    if [ -z "${latest}" ]; then
        echo "could not resolve any nano-8.x tarball" >&2
        exit 1
    fi
    VERSION="$(echo "${latest}" | sed -E 's/nano-(8\.[0-9]+)\.tar\.xz/\1/')"
    URL="https://www.nano-editor.org/dist/v8/nano-${VERSION}.tar.xz"
    SHA256=""   # unknown for a fallback release; computed + reported below
    echo "falling back to nano-${VERSION}" >&2
}

resolve_version

SRCDIR="${VDIR}/nano-${VERSION}"
TARBALL="${VDIR}/nano-${VERSION}.tar.xz"

if [ -d "${SRCDIR}" ]; then
    echo "nano-${VERSION} already extracted at ${SRCDIR}"
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
