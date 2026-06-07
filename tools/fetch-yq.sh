#!/usr/bin/env bash
# Fetch + verify the yq source tarball. Extracts under vendor/yq/.
# Idempotent. yq (github.com/mikefarah/yq) is a Go program — built
# static (CGO_ENABLED=0) per arch by vendor/yq/build.sh using the
# vendored Go SDK (vendor/go). Falls back to latest v4.x on 404.
set -euo pipefail
VERSION="4.44.3"
SHA256="ea950f5622480fc0ff3708c52589426a737cd4ec887a52922a74efa1be8f2fbf"
URL="https://github.com/mikefarah/yq/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/yq"
SRCDIR="${VDIR}/yq-${VERSION}"
TARBALL="${VDIR}/yq-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "yq-${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then
  echo "fetching ${URL}"
  if ! curl -fL -o "${TARBALL}" "${URL}"; then
    echo "fetch failed (404?) — resolving latest v4.x tag" >&2
    LATEST="$(curl -fsSL https://api.github.com/repos/mikefarah/yq/releases \
      | grep -oE '"tag_name": *"v4\.[0-9.]+"' | head -1 \
      | grep -oE 'v4\.[0-9.]+')"
    [ -n "${LATEST}" ] || { echo "could not resolve latest v4.x" >&2; exit 1; }
    VERSION="${LATEST#v}"
    SRCDIR="${VDIR}/yq-${VERSION}"
    TARBALL="${VDIR}/yq-${VERSION}.tar.gz"
    URL="https://github.com/mikefarah/yq/archive/refs/tags/v${VERSION}.tar.gz"
    [ -d "${SRCDIR}" ] && { echo "yq-${VERSION} already extracted"; exit 0; }
    echo "fetching ${URL}"
    curl -fL -o "${TARBALL}" "${URL}"
    SHA256=""
  fi
fi
if [ -n "${SHA256}" ]; then
  echo "verifying sha256"
  if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
    echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
    exit 1
  fi
else
  echo "computed sha256: $(sha256sum "${TARBALL}" | awk '{print $1}')"
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
