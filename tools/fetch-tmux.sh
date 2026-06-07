#!/usr/bin/env bash
# Fetch + verify tmux source tarball. Extracts under vendor/tmux/.
# Idempotent: skips download/extract if target tree already exists.
#
# tmux — terminal multiplexer. Vendored as static-musl C linked against
# the already-vendored libevent (libevent.a + event2/ headers) and
# ncurses (libncursesw.a). See vendor/tmux/build.sh.
set -euo pipefail

VERSION="3.5a"
SHA256="16216bd0877170dfcc64157085ba9013610b12b082548c7c9542cc0103198951"
URL="https://github.com/tmux/tmux/releases/download/${VERSION}/tmux-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/tmux"
SRCDIR="${VDIR}/tmux-${VERSION}"
TARBALL="${VDIR}/tmux-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "tmux-${VERSION} already extracted at ${SRCDIR}"
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
