#!/bin/sh
# Build the per-arch vDSO ELF blobs (linux-vdso.so.1 equivalent).
# Output: vdso-x86_64.so + vdso-aarch64.so, each a position-independent
# ET_DYN ELF with syscall-trampoline exports. Checked into
# kernel/blobs/ via the kernel's include_bytes! map at exec time.
#
# Per-arch toolchain:
#   x86_64  — system gcc (host).
#   aarch64 — vendored aarch64-linux-musl-cross (per `07§3`).

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../kernel/blobs"
mkdir -p "$out"

xcc="${CC:-gcc}"
acc="$here/../vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"

common="-nostdlib -shared -fPIC -fno-stack-protector
        -Wl,--hash-style=sysv
        -Wl,-Bsymbolic
        -Wl,--no-eh-frame-hdr
        -Wl,-z,noexecstack
        -Wl,-z,noseparate-code
        -Wl,-z,max-page-size=0x1000
        -Wl,-z,common-page-size=0x1000
        -Wl,-T,$here/vdso.lds"

echo "vdso: building vdso-x86_64.so"
$xcc $common \
    -Wl,-soname,linux-vdso.so.1 \
    -Wl,--build-id=none \
    -o "$out/vdso-x86_64.so" \
    "$here/vdso-x86_64.S"
strip --strip-debug --remove-section=.comment --remove-section=.note \
    "$out/vdso-x86_64.so"

if [ -x "$acc" ]; then
    echo "vdso: building vdso-aarch64.so"
    $acc $common \
        -Wl,-soname,linux-vdso.so.1 \
        -Wl,--build-id=none \
        -o "$out/vdso-aarch64.so" \
        "$here/vdso-aarch64.S"
    astrip="$here/../vendor/cross/aarch64-linux-musl-cross/bin/aarch64-linux-musl-strip"
    "$astrip" --strip-debug --remove-section=.comment --remove-section=.note \
        "$out/vdso-aarch64.so"
else
    echo "vdso: skip aarch64 (toolchain absent at $acc)"
fi

ls -la "$out"/vdso-*.so
