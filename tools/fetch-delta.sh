#!/usr/bin/env bash
# Fetch + verify delta (git-delta) source tarball. Extracts under vendor/delta/.
# Idempotent. Built static-musl per-arch by vendor/delta/build.sh.
# NOTE: delta release tags have no leading "v" (e.g. 0.18.2, not v0.18.2).
set -euo pipefail
VERSION="0.18.2"
SHA256="64717c3b3335b44a252b8e99713e080cbf7944308b96252bc175317b10004f02"
URL="https://github.com/dandavison/delta/archive/refs/tags/${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/delta"
SRCDIR="${VDIR}/delta-${VERSION}"
TARBALL="${VDIR}/delta-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "delta-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2; exit 1
fi
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
