#!/usr/bin/env bash
# Fetch + verify libevent source tarball. Extracts under vendor/libevent/.
# Idempotent: skips download/extract if target tree already exists.
#
# libevent is the event-loop dependency tmux links against. Vendored as a
# static-musl LIBRARY (install-<arch>/{lib,include}), not a rootfs program —
# tmux's build consumes libevent.a + event2/ headers at link time.
set -euo pipefail

VERSION="2.1.12-stable"
SHA256="92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb"
URL="https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libevent"
SRCDIR="${VDIR}/libevent-${VERSION}"
TARBALL="${VDIR}/libevent-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "libevent-${VERSION} already extracted at ${SRCDIR}"
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
