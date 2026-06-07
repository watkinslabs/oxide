#!/usr/bin/env bash
# Fetch + verify GNU bash source tarball. Extracts under vendor/bash/.
# Idempotent: skips download/extract if target tree already exists.
#
# F216: first GNU userspace program cross-built into the rootfs as a
# distro-pathway shakedown — bash exercises a wide libc and kernel
# surface (job control, signal handling, fork+exec patterns,
# /dev/tty redirection, large readline-free command line), so each
# gap surfaces a kernel/libc fix to land in the same PR per
# CLAUDE.md no-deferrals rule. bash is the shell.
set -euo pipefail

VERSION="5.2.37"
SHA256="9599b22ecd1d5787ad7d3b7bf0c59f312b3396d1e281175dd1f8a4014da621ff"
URL="https://ftp.gnu.org/gnu/bash/bash-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/bash"
SRCDIR="${VDIR}/bash-${VERSION}"
TARBALL="${VDIR}/bash-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "bash-${VERSION} already extracted at ${SRCDIR}"
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
