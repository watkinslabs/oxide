#!/usr/bin/env bash
# Fetch + verify libseccomp source tarball. Track L2 systemd dep (sandboxing).
set -euo pipefail
VERSION="2.5.5"
SHA256="248a2c8a4d9b9858aa6baf52712c34afefcf9c9e94b76dce02c1c9aa25fb3375"
URL="https://github.com/seccomp/libseccomp/releases/download/v${VERSION}/libseccomp-${VERSION}.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libseccomp"; SRCDIR="${VDIR}/libseccomp-${VERSION}"; TARBALL="${VDIR}/libseccomp-${VERSION}.tar.gz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libseccomp-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "libseccomp-${VERSION} ready; run vendor/libseccomp/build.sh"
