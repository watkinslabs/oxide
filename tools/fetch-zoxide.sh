#!/usr/bin/env bash
# Fetch + verify zoxide source tarball. Extracts under vendor/zoxide/.
# Idempotent. Built static-musl per-arch by vendor/zoxide/build.sh.
set -euo pipefail
VERSION="0.9.6"
SHA256="e1811511a4a9caafa18b7d1505147d4328b39f6ec88b88097fe0dad59919f19c"
URL="https://github.com/ajeetdsouza/zoxide/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/zoxide"
SRCDIR="${VDIR}/zoxide-${VERSION}"
TARBALL="${VDIR}/zoxide-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "zoxide-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
