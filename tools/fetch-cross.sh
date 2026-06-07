#!/usr/bin/sh
# Fetch the musl cross-toolchains from musl.cc into vendor/cross/.
# Idempotent — skips each fetch if that toolchain is already present.
# vendor/cross/ stays gitignored (~370 MiB of blobs).
#
# Output:
#   vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-{gcc,g++}
#   vendor/cross/x86_64-linux-musl-cross/bin/x86_64-linux-musl-{gcc,g++}
#
# aarch64: used by `xtask rootfs --arch aarch64` to produce arm-flavor
# userspace binaries that the aarch64 kernel can load.
#
# x86_64: musl-tools' host `musl-gcc` is C-only (no g++), so static-musl
# C++ programs (btop, …) can't build for x86_64 with it. This full musl.cc
# cross toolchain ships x86_64-linux-musl-g++, enabling C++ static-musl
# x86_64 builds matching the aarch64 path.
set -e

cd "$(dirname "$0")/../vendor"
mkdir -p cross
cd cross

# arch | tarball-stem | sha256 (musl.cc 11.2.1 toolchains)
fetch_one() {
  stem="$1"; sha="$2"
  if [ -x "${stem}/bin/${stem%-cross}-gcc" ]; then
    echo "fetch-cross: ${stem} already present"
    return 0
  fi
  tgz="${stem}.tgz"
  echo "fetch-cross: downloading ${stem}"
  curl -fsL "https://musl.cc/${tgz}" -o "${tgz}"
  if [ -n "${sha}" ]; then
    if ! echo "${sha}  ${tgz}" | sha256sum -c -; then
      actual="$(sha256sum "${tgz}" | awk '{print $1}')"
      echo "fetch-cross: sha256 mismatch for ${tgz} — got ${actual}" >&2
      echo "fetch-cross: upstream may have re-released; update sha in this script" >&2
      rm -f "${tgz}"
      exit 1
    fi
  fi
  tar xzf "${tgz}"
  rm -f "${tgz}"
  echo "fetch-cross: ${stem} ready at $(pwd)/${stem}"
}

fetch_one aarch64-linux-musl-cross ""
fetch_one x86_64-linux-musl-cross  "c5d410d9f82a4f24c549fe5d24f988f85b2679b452413a9f7e5f7b956f2fe7ea"
