# Cross-toolchains

`aarch64-linux-musl-cross/` — static prebuilt aarch64 musl-gcc 11.2.1
fetched once from <https://musl.cc/aarch64-linux-musl-cross.tgz>.

Used by `vendor/busybox/build.sh` to cross-build the aarch64 busybox
(`vendor/busybox/busybox-aarch64`) with the same config as the x86_64
build (`FEATURE_INSTALLER=n` per F147 + `SHA1/256_HWACCEL=n` for
arm64 since SHA-NI is x86-only).

Re-fetch:

    mkdir -p vendor/cross && cd vendor/cross
    curl -sL https://musl.cc/aarch64-linux-musl-cross.tgz | tar xz

Excluded from git via `vendor/.gitignore` (toolchain is ~370 MB
extracted; bandwidth-light fetch on demand).
