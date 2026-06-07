#!/usr/bin/env bash
# Fetch + verify tokei source tarball. Extracts under vendor/tokei/.
# Idempotent. Built static-musl per-arch by vendor/tokei/build.sh.
set -euo pipefail
VERSION="12.1.2"
SHA256="81ef14ab8eaa70a68249a299f26f26eba22f342fb8e22fca463b08080f436e50"
URL="https://github.com/XAMPPRocky/tokei/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/tokei"
SRCDIR="${VDIR}/tokei-${VERSION}"
TARBALL="${VDIR}/tokei-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "tokei-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
