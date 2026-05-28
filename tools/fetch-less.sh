#!/usr/bin/env bash
# Fetch + verify less source tarball. Extracts under vendor/less/.
# Idempotent.
#
# F254: vendor less for the distro buildout. The canonical pager
# every Linux distro ships. Static-musl + the F250 vendored ncurses.
set -euo pipefail

VERSION="643"
SHA256="2911b5432c836fa084c8a2e68f6cd6312372c026a58faaa98862731c8b6052e8"
URL="https://www.greenwoodsoftware.com/less/less-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/less"
SRCDIR="${VDIR}/less-${VERSION}"
TARBALL="${VDIR}/less-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "less-${VERSION} already extracted at ${SRCDIR}"
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
    exit 1
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
