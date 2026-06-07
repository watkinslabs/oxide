#!/usr/bin/env bash
# Fetch + verify btop source tarball. Extracts under vendor/btop/.
# Idempotent: skips download/extract if target tree already exists.
#
# btop — resource monitor TUI (CPU/mem/net/proc). C++20, Makefile build.
# Vendored as static-musl for x86_64 + aarch64 via the musl.cc cross
# toolchains (run tools/fetch-cross.sh first). Linux-only (reads /proc),
# which suits oxide's Linux-compatible userspace. Drops in at /usr/bin/btop.
set -euo pipefail

VERSION="1.4.0"
SHA256="ac0d2371bf69d5136de7e9470c6fb286cbee2e16b4c7a6d2cd48a14796e86650"
URL="https://github.com/aristocratos/btop/archive/refs/tags/v${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/btop"
SRCDIR="${VDIR}/btop-${VERSION}"
TARBALL="${VDIR}/btop-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "btop-${VERSION} already extracted at ${SRCDIR}"
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
