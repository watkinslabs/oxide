#!/usr/bin/env bash
# Fetch + verify util-linux source tarball. D1 of the distro roadmap:
# real distro programs (login, agetty, mount, su, umount, losetup,
# etc.). Static-musl cross-build via vendor/util-linux/build.sh.
set -euo pipefail

VERSION="2.40.2"
SHA256="d78b37a66f5922d70edf3bdfb01a6b33d34ed3c3cafd6628203b2a2b67c8e8b3"
URL="https://www.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-${VERSION}.tar.xz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/util-linux"
SRCDIR="${VDIR}/util-linux-${VERSION}"
TARBALL="${VDIR}/util-linux-${VERSION}.tar.xz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then
    echo "util-linux-${VERSION} already extracted"
    exit 0
fi
if [ ! -f "${TARBALL}" ]; then
    curl -fL -o "${TARBALL}" "${URL}"
fi
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "sha256 mismatch — got ${actual}" >&2
    exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
