#!/usr/bin/env bash
# Fetch + verify ripgrep source tarball. Extracts under vendor/ripgrep/.
# Idempotent. Built static-musl per-arch by vendor/ripgrep/build.sh.
set -euo pipefail
VERSION="14.1.1"
SHA256="4dad02a2f9c8c3c8d89434e47337aa654cb0e2aa50e806589132f186bf5c2b66"
URL="https://github.com/BurntSushi/ripgrep/archive/refs/tags/${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/ripgrep"
SRCDIR="${VDIR}/ripgrep-${VERSION}"
TARBALL="${VDIR}/ripgrep-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "ripgrep-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
