#!/usr/bin/env bash
# Fetch + verify dos2unix source tarball (line-ending converter; unix2dos).
# Makefile-based build (no autotools). Static-musl, NLS disabled.
set -euo pipefail

VERSION="7.5.2"
PRIMARY_URL="https://master.dl.sourceforge.net/project/dos2unix/dos2unix/${VERSION}/dos2unix-${VERSION}.tar.gz"
FALLBACK_URL="https://github.com/waterlan/dos2unix/archive/refs/tags/dos2unix-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/dos2unix"
SRCDIR="${VDIR}/dos2unix-${VERSION}"
TARBALL="${VDIR}/dos2unix-${VERSION}.tar.gz"
SHAFILE="${VDIR}/dos2unix-${VERSION}.tar.gz.sha256"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "dos2unix-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${PRIMARY_URL}"
    if ! curl -fL -o "${TARBALL}" "${PRIMARY_URL}"; then
        echo "primary 404/failed — trying github fallback ${FALLBACK_URL}"
        curl -fL -o "${TARBALL}" "${FALLBACK_URL}"
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

# GitHub archive extracts to dos2unix-dos2unix-<ver>/dos2unix-<ver>; normalize.
if [ ! -d "${SRCDIR}" ]; then
    cand="$(find "${VDIR}" -maxdepth 2 -type d -name "dos2unix-${VERSION}" | head -1 || true)"
    if [ -n "${cand}" ] && [ "${cand}" != "${SRCDIR}" ]; then
        mv "${cand}" "${SRCDIR}"
    fi
fi

echo "ready: ${SRCDIR}"
