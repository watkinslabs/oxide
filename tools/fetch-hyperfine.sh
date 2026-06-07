#!/usr/bin/env bash
# Fetch + verify hyperfine source tarball. Extracts under vendor/hyperfine/.
# Idempotent. Built static-musl per-arch by vendor/hyperfine/build.sh.
set -euo pipefail
VERSION="1.19.0"
SHA256="d1c782a54b9ebcdc1dedf8356a25ee11e11099a664a7d9413fdd3742138fa140"
URL="https://github.com/sharkdp/hyperfine/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/hyperfine"
SRCDIR="${VDIR}/hyperfine-${VERSION}"
TARBALL="${VDIR}/hyperfine-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "hyperfine-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
