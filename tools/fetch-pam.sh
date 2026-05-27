#!/usr/bin/env bash
# Fetch + verify Linux-PAM source tarball. Extracts under vendor/pam/.
# Idempotent: skips download/extract if target tree already exists.
set -euo pipefail

VERSION="1.7.2"
SHA256="3d86b6383fb5fd9eb9578d2cd47d92801191f4bf3f9bc61419bfefc8aa1e531a"
URL="https://github.com/linux-pam/linux-pam/releases/download/v${VERSION}/Linux-PAM-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/pam"
SRCDIR="${VDIR}/Linux-PAM-${VERSION}"
TARBALL="${VDIR}/Linux-PAM-${VERSION}.tar.xz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "Linux-PAM-${VERSION} already extracted at ${SRCDIR}"
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
