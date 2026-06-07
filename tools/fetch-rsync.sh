#!/usr/bin/env bash
# Fetch + verify rsync source tarball. Extracts under vendor/rsync/.
# Idempotent: skips download/extract if target tree already exists.
#
# rsync is the incremental file-transfer/sync utility. Built static-musl
# both arches with bundled popt + bundled zlib so it needs no external
# vendored libs (compression/crypto extras are disabled). Each gap it
# surfaces (mmap, fork+exec, socketpair, select/poll, *at syscalls)
# closes in the same PR per CLAUDE.md no-deferrals rule.
set -euo pipefail

VERSION="3.3.0"
SHA256="7399e9a6708c32d678a72a63219e96f23be0be2336e50fd1348498d07041df90"
URL="https://download.samba.org/pub/rsync/src/rsync-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/rsync"
SRCDIR="${VDIR}/rsync-${VERSION}"
TARBALL="${VDIR}/rsync-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "rsync-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    if ! curl -fL -o "${TARBALL}" "${URL}"; then
        echo "404/fetch failed for ${VERSION} — fetch latest rsync-3.x and update VERSION/SHA256" >&2
        exit 1
    fi
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
