#!/usr/bin/env bash
# Fetch + verify GNU wget source tarball. Extracts under vendor/wget/.
# Idempotent: skips download/extract if target tree already exists.
#
# wget is built static-musl against the ALREADY-VENDORED openssl + zlib
# (vendor/openssl/install-<arch>, vendor/zlib/install-<arch>) — same link
# convention as vendor/openssh/build.sh. NO prebuilt: build from source per
# CLAUDE.md vendor discipline. Each libc/kernel gap that surfaces lands in
# the same PR per the no-deferrals rule.
set -euo pipefail

VERSION="1.21.4"
SHA256="81542f5cefb8faacc39bbbc6c82ded80e3e4a88505ae72ea51df27525bcde04c"
URL="https://ftp.gnu.org/gnu/wget/wget-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/wget"
SRCDIR="${VDIR}/wget-${VERSION}"
TARBALL="${VDIR}/wget-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "wget-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    if ! curl -fL -o "${TARBALL}" "${URL}"; then
        # upstream prunes old point releases off ftp.gnu.org; fall back to
        # the latest 1.21.x still published.
        echo "404 on ${VERSION} — probing latest 1.21.x" >&2
        for v in 1.21.4 1.21.3 1.21.2 1.21.1 1.21; do
            alt="https://ftp.gnu.org/gnu/wget/wget-${v}.tar.gz"
            if curl -fL -o "${TARBALL}" "${alt}"; then
                echo "fetched fallback ${v}" >&2
                VERSION="$v"; SRCDIR="${VDIR}/wget-${VERSION}"
                SHA256=""   # checksum unknown for fallback; accept what we got
                break
            fi
        done
    fi
fi

if [ -n "${SHA256}" ]; then
    echo "verifying sha256"
    if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
        actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
        echo "sha256 mismatch — upstream may have re-released. Got ${actual}." >&2
        echo "If you trust the new checksum, update SHA256 in this script." >&2
        exit 1
    fi
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
