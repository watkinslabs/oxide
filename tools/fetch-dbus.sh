#!/usr/bin/env bash
# Fetch + verify dbus source tarball. Track L2: mandatory systemd bus stack.
set -euo pipefail
VERSION="1.14.10"
SHA256="ba1f21d2bd9d339da2d4aa8780c09df32fea87998b73da24f49ab9df1e36a50f"
URL="https://dbus.freedesktop.org/releases/dbus/dbus-${VERSION}.tar.xz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/dbus"; SRCDIR="${VDIR}/dbus-${VERSION}"; TARBALL="${VDIR}/dbus-${VERSION}.tar.xz"
mkdir -p "${VDIR}"
if [ -d "${SRCDIR}" ]; then echo "dbus-${VERSION} already extracted"; exit 0; fi
[ -f "${TARBALL}" ] || curl -sL --connect-timeout 15 -o "${TARBALL}" "${URL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -
tar -xJf "${TARBALL}" -C "${VDIR}"
echo "dbus-${VERSION} ready; run vendor/dbus/build.sh (needs vendor/expat built first)"
