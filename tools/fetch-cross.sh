#!/usr/bin/sh
# Fetch the aarch64 musl cross-toolchain from musl.cc into
# vendor/cross/. ~108 MiB tarball, ~322 MiB extracted. Idempotent —
# skips the fetch if the toolchain is already present.
#
# Output:
#   vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
#
# Used by `xtask rootfs --arch aarch64` to produce arm-flavor
# userspace binaries that the aarch64 kernel can load.
set -e

cd "$(dirname "$0")/../vendor"
mkdir -p cross
cd cross

if [ -x aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc ]; then
  echo "fetch-cross: aarch64 toolchain already present"
  exit 0
fi

curl -fsL https://musl.cc/aarch64-linux-musl-cross.tgz -o aarch64.tgz
tar xzf aarch64.tgz
rm aarch64.tgz
echo "fetch-cross: aarch64 toolchain ready at $(pwd)/aarch64-linux-musl-cross"
