#!/usr/bin/env bash
# Fetch + verify the duf source tarball. Extracts under vendor/duf/.
# Idempotent. duf is a Go program (df alternative) — built static
# (CGO_ENABLED=0) per arch by vendor/duf/build.sh using the vendored
# Go SDK (vendor/go). If the pinned tag 404s, falls back to the latest
# v0.x tag.
set -euo pipefail
VERSION="0.8.1"
SHA256="ebc3880540b25186ace220c09af859f867251f4ecaef435525a141d98d71a27a"
URL="https://github.com/muesli/duf/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/duf"
SRCDIR="${VDIR}/duf-${VERSION}"
TARBALL="${VDIR}/duf-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "duf-${VERSION} already extracted"; exit 0; fi
if [ ! -f "${TARBALL}" ]; then
  echo "fetching ${URL}"
  if ! curl -fL -o "${TARBALL}" "${URL}"; then
    echo "tag v${VERSION} fetch failed — resolving latest v0.x tag" >&2
    LATEST="$(curl -fsSL https://api.github.com/repos/muesli/duf/tags \
      | grep -o '"name": *"v0\.[0-9.]*"' | head -n1 | grep -o 'v0\.[0-9.]*')"
    [ -n "${LATEST}" ] || { echo "could not resolve latest v0.x tag" >&2; exit 1; }
    echo "latest = ${LATEST}; edit VERSION/SHA256 in this script to pin it" >&2
    exit 1
  fi
fi
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
  exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
