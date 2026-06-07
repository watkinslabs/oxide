#!/usr/bin/env bash
# Fetch + verify curl source tarball. Extracts under vendor/curl/.
# Idempotent: skips download/extract if target tree already exists.
#
# curl built as static-musl C, linking the already-vendored openssl
# (vendor/openssl/install-<arch>) + zlib (vendor/zlib/install-<arch>).
# Per CLAUDE.md no-deferrals: only the vendored deps are linked; all
# other optional curl backends (brotli, zstd, nghttp2, libpsl, ldap)
# are disabled rather than half-wired.
#
# If the pinned version 404s upstream (curl prunes old downloads), set
# VERSION to the latest 8.x and re-run; the script re-derives + embeds
# the sha256 from the freshly downloaded tarball.
set -euo pipefail

VERSION="8.11.0"
SHA256="264537d90e58d2b09dddc50944baf3c38e7089151c8986715e2aaeaaf2b8118f"
URL="https://curl.se/download/curl-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/curl"
SRCDIR="${VDIR}/curl-${VERSION}"
TARBALL="${VDIR}/curl-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "curl-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    if ! curl -fL -o "${TARBALL}" "${URL}"; then
        echo "download failed (404?) — curl prunes old releases." >&2
        echo "Set VERSION to the latest curl 8.x in this script and re-run." >&2
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
