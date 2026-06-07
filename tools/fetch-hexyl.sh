#!/usr/bin/env bash
# Fetch + verify hexyl source tarball. Extracts under vendor/hexyl/.
# Idempotent. Built static-musl per-arch by vendor/hexyl/build.sh.
set -euo pipefail
VERSION="0.15.0"
SHA256="017ab7fe18caa3d13427fb13fd6050a9d8bf9aa26d1e1fe02924dfd7f86cd3cf"
URL="https://github.com/sharkdp/hexyl/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/hexyl"
SRCDIR="${VDIR}/hexyl-${VERSION}"
TARBALL="${VDIR}/hexyl-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "hexyl-${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then
  echo "fetching ${URL}"
  if ! curl -fL -o "${TARBALL}" "${URL}"; then
    echo "v${VERSION} fetch failed (404?) — finding latest v0.x" >&2
    LATEST="$(curl -fsSL https://api.github.com/repos/sharkdp/hexyl/tags \
      | grep -oE '"name": *"v0\.[0-9]+\.[0-9]+"' | head -1 \
      | grep -oE 'v0\.[0-9]+\.[0-9]+')"
    [ -n "${LATEST}" ] || { echo "could not resolve latest v0.x" >&2; exit 1; }
    VERSION="${LATEST#v}"
    URL="https://github.com/sharkdp/hexyl/archive/refs/tags/v${VERSION}.tar.gz"
    SRCDIR="${VDIR}/hexyl-${VERSION}"
    TARBALL="${VDIR}/hexyl-${VERSION}.tar.gz"
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
  fi
fi
REAL="$(sha256sum "${TARBALL}" | awk '{print $1}')"
if [ -z "${SHA256}" ]; then
  echo "embedding sha256 ${REAL}"
  sed -i "s/^SHA256=\"\"/SHA256=\"${REAL}\"/" "$0"
  SHA256="${REAL}"
fi
echo "verifying sha256"
if [ "${SHA256}" != "${REAL}" ]; then
  echo "sha256 mismatch — got ${REAL}" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
