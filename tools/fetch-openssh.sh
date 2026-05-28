#!/usr/bin/env bash
# Fetch + verify openssh-portable source tarball. Extracts under
# vendor/openssh/. Idempotent: skips download/extract if target tree
# already exists.
#
# F210: oxide2 ships openssh-portable (not dropbear) so the standard
# Linux PTY + channel semantics drive the SSH server. dropbear's
# CHANNEL_EOF → close-master heuristic breaks `ssh -tt 'cmd' < /dev/null`
# both in real Linux and our kernel; openssh's send-eof + drain
# semantic handles that case correctly.
set -euo pipefail

VERSION="9.9p2"
SHA256="91aadb603e08cc285eddf965e1199d02585fa94d994d6cae5b41e1721e215673"
URL="https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/openssh"
SRCDIR="${VDIR}/openssh-${VERSION}"
TARBALL="${VDIR}/openssh-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "openssh-${VERSION} already extracted at ${SRCDIR}"
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
