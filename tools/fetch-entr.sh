#!/usr/bin/env bash
# Fetch + verify entr source tarball (run commands when files change).
# Custom ./configure (writes config.mk) + Makefile — no autotools/deps.
# Static-musl, inotify backend (auto-detected on Linux).
set -euo pipefail

VERSION="5.6"
PRIMARY_URL="https://github.com/eradman/entr/archive/refs/tags/${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/entr"
SRCDIR="${VDIR}/entr-${VERSION}"
TARBALL="${VDIR}/entr-${VERSION}.tar.gz"
SHAFILE="${VDIR}/entr-${VERSION}.tar.gz.sha256"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "entr-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

# Idempotent fetch; fall back to latest 5.x if the pinned tag 404s.
fetch_tag() {
    local ver="$1"
    curl -fL -o "${TARBALL}" "https://github.com/eradman/entr/archive/refs/tags/${ver}.tar.gz"
}

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${PRIMARY_URL}"
    if ! fetch_tag "${VERSION}"; then
        echo "tag ${VERSION} 404/failed — resolving latest 5.x tag" >&2
        latest="$(curl -fsSL https://api.github.com/repos/eradman/entr/tags \
            | grep -oE '"name": *"5\.[0-9.]+"' | head -1 | grep -oE '5\.[0-9.]+' || true)"
        if [ -z "${latest}" ]; then
            echo "could not resolve a 5.x tag from GitHub API" >&2
            exit 1
        fi
        echo "latest 5.x = ${latest}"
        VERSION="${latest}"
        SRCDIR="${VDIR}/entr-${VERSION}"
        TARBALL="${VDIR}/entr-${VERSION}.tar.gz"
        SHAFILE="${VDIR}/entr-${VERSION}.tar.gz.sha256"
        fetch_tag "${VERSION}"
    fi
fi

# Compute + embed real sha256 on first fetch; verify on subsequent runs.
actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
if [ ! -f "${SHAFILE}" ]; then
    echo "${actual}" > "${SHAFILE}"
    echo "recorded sha256 ${actual} → ${SHAFILE}"
else
    expected="$(cat "${SHAFILE}")"
    if [ "${actual}" != "${expected}" ]; then
        echo "sha256 mismatch — expected ${expected} got ${actual}" >&2
        exit 1
    fi
    echo "sha256 verified ${actual}"
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
