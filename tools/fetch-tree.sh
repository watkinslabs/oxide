#!/usr/bin/env bash
# Fetch + verify unix-tree (the directory lister) source tarball.
# Extracts under vendor/tree/unix-tree-2.2.1/.
# Idempotent: skips download/extract if target tree already exists.
#
# tree is a small plain-Makefile C program (no autotools); cross-built
# static-musl into the rootfs as a distro program per CLAUDE.md
# (real vendor cross-builds, never hand-rolled). Maintained source is
# the OldManProgrammer unix-tree fork on GitLab.
set -euo pipefail

VERSION="2.2.1"
SHA256="70d9c6fc7c5f4cb1f7560b43e2785194594b9b8f6855ab53376f6bd88667ee04"
URL="https://gitlab.com/OldManProgrammer/unix-tree/-/archive/${VERSION}/unix-tree-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/tree"
SRCDIR="${VDIR}/unix-tree-${VERSION}"
TARBALL="${VDIR}/unix-tree-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "unix-tree-${VERSION} already extracted at ${SRCDIR}"
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
