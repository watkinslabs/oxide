#!/usr/bin/env bash
# Fetch the Go SDK for the BUILD HOST (x86_64 linux) into vendor/go/.
# ~70 MiB tarball, ~500 MiB extracted. The tarball has a top-level
# `go/` dir; extracting with `tar -C vendor` yields vendor/go/bin/go.
# Idempotent — skips if vendor/go/bin/go already exists.
#
# Go cross-compiles natively (GOOS/GOARCH), so this single host SDK
# builds binaries for every oxide arch — no per-arch cross-toolchain.
#
# vendor/go/ is a fetched build tool (~500 MiB) — stays gitignored
# like vendor/cross. Do NOT add a vendor/.gitignore allowlist for it.
set -euo pipefail
VERSION="1.23.4"
SHA256="6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971"
URL="https://go.dev/dl/go${VERSION}.linux-amd64.tar.gz"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDIR="${ROOT}/vendor/go"
TARBALL="${VDIR}/go${VERSION}.linux-amd64.tar.gz"

if [ -x "${VDIR}/bin/go" ]; then
  echo "fetch-go: Go SDK already present at ${VDIR}/bin/go"
  exit 0
fi

mkdir -p "${ROOT}/vendor"
mkdir -p "${VDIR}"
[ -f "${TARBALL}" ] || { echo "fetching ${URL}"; curl -fL -o "${TARBALL}" "${URL}"; }

echo "verifying sha256"
if ! echo "${SHA256}  ${TARBALL}" | sha256sum -c -; then
  echo "sha256 mismatch — got $(sha256sum "${TARBALL}" | awk '{print $1}')" >&2
  exit 1
fi

# Tarball top-level is `go/`. Extract into a tmp staging dir, then move
# its contents up so the binary lands at vendor/go/bin/go (not
# vendor/go/go/bin/go). --strip-components=1 drops the leading `go/`.
STAGE="$(mktemp -d "${VDIR}/.extract.XXXXXX")"
tar -C "${STAGE}" --strip-components=1 -xf "${TARBALL}"
mv "${STAGE}"/* "${VDIR}/"
rmdir "${STAGE}"
rm -f "${TARBALL}"
echo "fetch-go: Go SDK ready at ${VDIR}/bin/go"
