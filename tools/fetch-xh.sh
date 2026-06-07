#!/usr/bin/env bash
# Fetch + verify xh source tarball. Extracts under vendor/xh/.
# Idempotent. Built static-musl per-arch by vendor/xh/build.sh.
# Falls back to latest v0.x release if the pinned tag 404s.
set -euo pipefail
VERSION="0.23.0"
SHA256="c44ca41b52b5857895d0118b44075d94c3c4a98b025ed3433652519a1ff967a0"
TAG="v${VERSION}"
URL="https://github.com/ducaale/xh/archive/refs/tags/${TAG}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/xh"
SRCDIR="${VDIR}/xh-${VERSION}"
TARBALL="${VDIR}/xh-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "xh-${VERSION} already extracted"; exit 0; fi

fetch() {
  echo "fetching $1"
  curl -fL -o "${TARBALL}" "$1"
}

if ! fetch "${URL}"; then
  echo "tag ${TAG} 404 — resolving latest v0.x release" >&2
  LATEST="$(curl -fsSL https://api.github.com/repos/ducaale/xh/releases \
    | grep -oE '"tag_name": *"v0\.[0-9.]+"' | head -n1 | grep -oE 'v0\.[0-9.]+')"
  [ -n "${LATEST}" ] || { echo "could not resolve latest v0.x" >&2; exit 1; }
  VERSION="${LATEST#v}"
  TAG="${LATEST}"
  SRCDIR="${VDIR}/xh-${VERSION}"
  TARBALL="${VDIR}/xh-${VERSION}.tar.gz"
  if [ -d "${SRCDIR}" ]; then echo "xh-${VERSION} already extracted"; exit 0; fi
  fetch "https://github.com/ducaale/xh/archive/refs/tags/${TAG}.tar.gz"
  SHA256=""
fi

if [ -n "${SHA256}" ]; then
  echo "verifying sha256"
  if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
  fi
else
  echo "sha256 (fallback release): $(sha256sum "${TARBALL}" | awk '{print $1}')"
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
