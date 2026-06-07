#!/usr/bin/env bash
# Fetch + verify jq source tarball (release bundle with deps). Extracts
# under vendor/jq/. Idempotent: skips download/extract if tree exists.
#
# jq 1.7.1 — JSON processor used across distro scripts/tooling. The
# release tarball bundles its build deps (oniguruma via --with-oniguruma=
# builtin), so a static-musl cross-build needs no external libs. Pure
# userspace: no kernel UAPI surface beyond standard libc.
set -euo pipefail

VERSION="1.7.1"
SHA256="478c9ca129fd2e3443fe27314b455e211e0d8c60bc8ff7df703873deeee580c2"
URL="https://github.com/jqlang/jq/releases/download/jq-${VERSION}/jq-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/jq"
SRCDIR="${VDIR}/jq-${VERSION}"
TARBALL="${VDIR}/jq-${VERSION}.tar.gz"

mkdir -p "${VDIR}"

if [ -d "${SRCDIR}" ]; then
    echo "jq-${VERSION} already extracted at ${SRCDIR}"
    exit 0
fi

if [ ! -f "${TARBALL}" ]; then
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
fi

if [ -n "${SHA256}" ]; then
    echo "verifying sha256"
    if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
        actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
        echo "sha256 mismatch — upstream may have re-released. Got ${actual}." >&2
        echo "If you trust the new checksum, update SHA256 in this script." >&2
        exit 1
    fi
else
    actual="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    echo "no SHA256 pinned yet; observed ${actual}" >&2
    echo "embed this into SHA256= in fetch-jq.sh" >&2
    exit 1
fi

echo "extracting"
tar -C "${VDIR}" -xf "${TARBALL}"

echo "ready: ${SRCDIR}"
