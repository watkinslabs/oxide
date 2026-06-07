#!/usr/bin/env bash
# Fetch + verify pv (pipe viewer) source tarball. Extracts under vendor/pv/.
# Idempotent: skips download/extract if target tree already exists.
#
# pv (ivarch.com/programs/pv) is a terminal progress meter for piped data.
# Static-musl autotools build, no special deps — a non-TUI CLI shakedown of
# the read/write/poll/ioctl(TIOCGWINSZ)/select libc surface in the rootfs.
set -euo pipefail

VERSION="1.8.5"
SHA256="d22948d06be06a5be37336318de540a2215be10ab0163f8cd23a20149647b780"
URL="https://www.ivarch.com/programs/sources/pv-${VERSION}.tar.gz"
MIRROR="https://github.com/icetee/pv/archive/refs/tags/v${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/pv"
SRCDIR="${VDIR}/pv-${VERSION}"
TARBALL="${VDIR}/pv-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "pv-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    if ! curl -fL -o "${TARBALL}" "${URL}"; then
        echo "primary failed, trying github mirror ${MIRROR}"
        curl -fL -o "${TARBALL}" "${MIRROR}"
    fi
fi

echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch — upstream/mirror tarballs differ or re-released. Got ${actual}." >&2
    echo "If you trust the new checksum, update SHA256 in this script." >&2
    exit 1
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

# github mirror unpacks as pv-${VERSION} too (tag v1.8.5 → pv-1.8.5); normalize
# any other top-level dir name just in case.
if [ ! -d "${SRCDIR}" ]; then
    top="$(tar -tf "${TARBALL}" | head -1 | cut -d/ -f1)"
    if [ -n "${top}" ] && [ -d "${VDIR}/${top}" ]; then
        mv "${VDIR}/${top}" "${SRCDIR}"
    fi
fi

echo "ready: ${SRCDIR}"
