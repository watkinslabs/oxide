# Cross-toolchains

`aarch64-linux-musl-cross/` — static prebuilt aarch64 musl-gcc 11.2.1
fetched once from <https://musl.cc/aarch64-linux-musl-cross.tgz>.

Used by the per-package `build.sh` recipes (bash, coreutils,
util-linux, etc.) to cross-build their aarch64 static-musl binaries
with the same config as the x86_64 build.

Re-fetch:

    mkdir -p vendor/cross && cd vendor/cross
    curl -sL https://musl.cc/aarch64-linux-musl-cross.tgz | tar xz

Excluded from git via `vendor/.gitignore` (toolchain is ~370 MB
extracted; bandwidth-light fetch on demand).
