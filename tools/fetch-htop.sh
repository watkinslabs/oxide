#!/usr/bin/env bash
# Fetch + verify htop source tarball. Extracts under vendor/htop/.
# Idempotent: skips download/extract if target tree already exists.
#
# htop — interactive process viewer (NCurses TUI). Vendored as static-musl
# C linked against the already-vendored ncurses (libncursesw.a). The 3.x
# line is C (autotools), which fits the C cross-build pathway. Pin 3.3.0;
# if upstream 404s that release, the script falls forward to the latest
# 3.x release tag via the GitHub API and re-derives the sha256.
set -euo pipefail

VERSION="3.3.0"
SHA256="a69acf9b42ff592c4861010fce7d8006805f0d6ef0e8ee647a6ee6e59b743d5c"
URL="https://github.com/htop-dev/htop/releases/download/${VERSION}/htop-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/htop"
SRCDIR="${VDIR}/htop-${VERSION}"
TARBALL="${VDIR}/htop-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "htop-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    if ! curl -fL -o "${TARBALL}" "${URL}"; then
        echo "fetch of ${VERSION} failed (404?) — resolving latest 3.x release" >&2
        latest="$(curl -fsSL https://api.github.com/repos/htop-dev/htop/releases \
            | grep -oE '"tag_name": *"3\.[0-9.]+"' | head -1 \
            | sed -E 's/.*"(3\.[0-9.]+)".*/\1/')"
        if [ -z "${latest}" ]; then
            echo "could not resolve a latest 3.x release tag" >&2
            exit 1
        fi
        echo "falling forward to htop-${latest}" >&2
        VERSION="${latest}"
        SRCDIR="${VDIR}/htop-${VERSION}"
        TARBALL="${VDIR}/htop-${VERSION}.tar.xz"
        URL="https://github.com/htop-dev/htop/releases/download/${VERSION}/htop-${VERSION}.tar.xz"
        SHA256=""  # unknown for fallback; computed + reported below
        [ -d "${SRCDIR}" ] && { echo "htop-${VERSION} already extracted"; exit 0; }
        curl -fL -o "${TARBALL}" "${URL}"
    fi
fi

if [ -n "${SHA256}" ]; then
    echo "verifying sha256"
    if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
        actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
        echo "sha256 mismatch — upstream may have re-released. Got ${actual}." >&2
        echo "If you trust the new checksum, update SHA256 in this script." >&2
        exit 1
    fi
else
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "fallback release ${VERSION} sha256=${actual} (update SHA256 + VERSION to pin)"
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
