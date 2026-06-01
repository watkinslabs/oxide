#!/usr/bin/env bash
# Fetch + verify systemd source. Track D6: the init/service manager.
set -euo pipefail
VERSION="259"
SHA256="a84123692d1add7f9c48fd11cdf5f901393008c2d2ade667c18f25a20bf1290d"
URL="https://github.com/systemd/systemd/archive/refs/tags/v${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/systemd"; SRCDIR="${VDIR}/systemd-${VERSION}"; TARBALL="${VDIR}/systemd-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "systemd-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 20 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "systemd-${VERSION} ready; run vendor/systemd/build.sh (needs L2 .pc files + meson cross files)"
