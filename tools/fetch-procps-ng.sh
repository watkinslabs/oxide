#!/usr/bin/env bash
# Fetch procps-ng. D3 of the distro roadmap.
set -euo pipefail

VERSION="4.0.5"
# Sourceforge release tarball ships pre-built configure (no autopoint needed).
SHA256="c2e6d193cc78f84cd6ddb72aaf6d5c6a9162f0470e5992092057f5ff518562fa"
URL="https://sourceforge.net/projects/procps-ng/files/Production/procps-ng-${VERSION}.tar.xz/download"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/procps-ng"
SRCDIR="${VDIR}/procps-ng-${VERSION}"
TARBALL="${VDIR}/procps-ng-${VERSION}.tar.xz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "procps-${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then curl -fL -o "${TARBALL}" "${URL}"; fi
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch -- got ${actual}" >&2
    exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
