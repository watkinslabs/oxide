#!/usr/bin/env bash
# Fetch + verify CPython source. Extracts under vendor/python/. Idempotent.
# Roadmap item 4: vendor a static-musl CPython for the OXIDE distro.
set -euo pipefail

VERSION="3.13.1"
SHA256="1513925a9f255ef0793dbf2f78bb4533c9f184bdd0ad19763fd7f47a400a7c55"
URL="https://www.python.org/ftp/python/${VERSION}/Python-${VERSION}.tgz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/python"
SRCDIR="${VDIR}/Python-${VERSION}"
TARBALL="${VDIR}/Python-${VERSION}.tgz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "Python-${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then curl -fsSL -o "${TARBALL}" "${URL}"; fi
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -C "${VDIR}" -xzf "${TARBALL}"
echo "extracted ${SRCDIR}"
