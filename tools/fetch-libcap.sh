#!/usr/bin/env bash
# Fetch + verify libcap source tarball.
# Track L2: first systemd shared dep (libcap.so → /usr/lib).
set -euo pipefail

VERSION="2.69"
SHA256="3a99ec26452e328e0ea408efd67096ef914f4ee4788fa8e8e21f214e2bd670b9"
URL="https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${VERSION}.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/libcap"
SRCDIR="${VDIR}/libcap-${VERSION}"
TARBALL="${VDIR}/libcap-${VERSION}.tar.gz"

mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "libcap-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xzf "${TARBALL}" -C "${VDIR}"
echo "libcap-${VERSION} ready; run vendor/libcap/build.sh"
