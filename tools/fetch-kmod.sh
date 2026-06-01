#!/usr/bin/env bash
# Fetch + verify kmod source. Track L2: systemd-modules-load/udev libkmod dep.
set -euo pipefail
VERSION="31"
SHA256="f5a6949043cc72c001b728d8c218609c5a15f3c33d75614b78c79418fcf00d80"
URL="https://mirrors.edge.kernel.org/pub/linux/utils/kernel/kmod/kmod-${VERSION}.tar.xz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/kmod"; SRCDIR="${VDIR}/kmod-${VERSION}"; TARBALL="${VDIR}/kmod-${VERSION}.tar.xz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "kmod-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xJf "${TARBALL}" -C "${VDIR}"
echo "kmod-${VERSION} ready; run vendor/kmod/build.sh"
