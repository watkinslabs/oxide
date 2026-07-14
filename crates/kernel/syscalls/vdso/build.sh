#!/bin/sh
# Build the per-arch vDSO ELF blobs (linux-vdso.so.1 equivalent).
# Output: vdso-x86_64.so + vdso-aarch64.so, each a position-independent
# ET_DYN ELF with syscall-trampoline exports. Checked into
# kernel/blobs/ via the kernel's include_bytes! map at exec time.
#
# Per-arch toolchain:
#   x86_64  — system gcc (host).
#   aarch64 — clang + LLD targeting aarch64-unknown-linux-gnu (`07§3`).

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
out="$here"
mkdir -p "$out"
xcc="${CC:-gcc}"
xstrip="${STRIP:-strip}"
acc="${AARCH64_CC:-clang}"
astrip="${AARCH64_STRIP:-llvm-strip}"

for tool in "$xcc" "$xstrip" "$acc" ld.lld "$astrip"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "vdso: required tool not found: $tool" >&2
        exit 1
    fi
done

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
"$xcc" $common \
    -Wl,-soname,linux-vdso.so.1 \
    -Wl,--build-id=none \
    -o "$out/vdso-x86_64.so" \
    "$here/vdso-x86_64.S"
"$xstrip" --strip-debug --remove-section=.comment --remove-section=.note \
    "$out/vdso-x86_64.so"

echo "vdso: building vdso-aarch64.so (aarch64-unknown-linux-gnu)"
"$acc" --target=aarch64-unknown-linux-gnu -fuse-ld=lld $common \
    -Wl,--undefined-version \
    -Wl,-soname,linux-vdso.so.1 \
    -Wl,--build-id=none \
    -o "$out/vdso-aarch64.so" \
    "$here/vdso-aarch64.S"
"$astrip" --strip-debug --remove-section=.comment --remove-section=.note \
    "$out/vdso-aarch64.so"

ls -la "$out"/vdso-*.so
