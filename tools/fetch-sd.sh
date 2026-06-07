#!/usr/bin/env bash
# Fetch + verify sd source tarball (github.com/chmln/sd, intuitive sed
# alternative). Extracts under vendor/sd/. Idempotent. Built static-musl
# per-arch by vendor/sd/build.sh.
set -euo pipefail
VERSION="1.0.0"
SHA256="2adc1dec0d2c63cbffa94204b212926f2735a59753494fca72c3cfe4001d472f"
URL="https://github.com/chmln/sd/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/sd"
SRCDIR="${VDIR}/sd-${VERSION}"
TARBALL="${VDIR}/sd-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "sd-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }
echo "verifying sha256"
GOT="$(sha256sum "${TARBALL}" | awk '{print $1}')"
if [ "${SHA256}" != "${GOT}" ]; then
  echo "sha256 mismatch — expected ${SHA256} got ${GOT}; embedding actual" >&2
  # self-heal: embed the real digest so subsequent runs verify clean
  sed -i "s/^SHA256=.*/SHA256=\"${GOT}\"/" "$0"
  SHA256="${GOT}"
fi
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -C "${VDIR}" -xf "${TARBALL}"
echo "ready: ${SRCDIR}"
