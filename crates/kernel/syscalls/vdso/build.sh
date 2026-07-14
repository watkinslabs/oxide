#!/bin/sh
# Build the per-arch vDSO ELF blobs (linux-vdso.so.1 equivalent).
# Usage: build.sh <x86_64|aarch64|all>. Output is a position-independent
# ET_DYN ELF consumed by the kernel's include_bytes! map at exec time.
#
# Per-arch toolchain:
#   x86_64  — system gcc (host).
#   aarch64 — clang + LLD targeting aarch64-unknown-linux-gnu (`07§3`).

set -eu
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd)"
out="$here"
mkdir -p "$out"
xcc="${CC:-gcc}"
xstrip="${STRIP:-strip}"
acc="${AARCH64_CC:-clang}"
astrip="${AARCH64_STRIP:-llvm-strip}"
arch="${1:-all}"

common="-nostdlib -shared -fPIC -fno-stack-protector
        -Wl,--hash-style=sysv
        -Wl,-Bsymbolic
        -Wl,--no-eh-frame-hdr
        -Wl,-z,noexecstack
        -Wl,-z,noseparate-code
        -Wl,-z,max-page-size=0x1000
        -Wl,-z,common-page-size=0x1000
        -Wl,-T,$here/vdso.lds"

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "vdso: required tool not found: $1" >&2
        exit 1
    fi
}

validate() {
    file="$1" machine="$2" version="$3" expected="$4"
    test "$(readelf -h "$file" | awk -F: '/Type:/ { gsub(/ /, "", $2); print $2 }')" = "DYN(Sharedobjectfile)"
    test "$(readelf -h "$file" | awk -F: '/Machine:/ { sub(/^[[:space:]]*/, "", $2); print $2 }')" = "$machine"
    readelf -dW "$file" | grep -Fq 'Library soname: [linux-vdso.so.1]'
    test "$(readelf -lW "$file" | awk '$1 == "LOAD" { n++ } END { print n + 0 }')" -eq 1
    test "$(readelf -lW "$file" | awk '$1 == "LOAD" && $(NF-2) == "R" && $(NF-1) == "E" { n++ } END { print n + 0 }')" -eq 1
    readelf -rW "$file" | grep -Fq 'There are no relocations in this file.'
    readelf -VW "$file" | grep -Fq "Name: $version"
    actual="$(readelf --dyn-syms --wide "$file" |
        awk '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" { print $8 }' | sort)"
    test "$actual" = "$expected"
}

build_x86() {
    need "$xcc"; need "$xstrip"; need readelf
    echo "vdso: building vdso-x86_64.so"
    "$xcc" $common -Wl,--version-script="$here/vdso-x86_64.map" \
        -Wl,-soname,linux-vdso.so.1 -Wl,--build-id=none \
        -o "$out/vdso-x86_64.so" "$here/vdso-x86_64.S"
    "$xstrip" --strip-debug --remove-section=.comment --remove-section=.note \
        "$out/vdso-x86_64.so"
    validate "$out/vdso-x86_64.so" "Advanced Micro Devices X86-64" "LINUX_2.6" \
        "$(printf '%s@@LINUX_2.6\n' __vdso_clock_getres __vdso_clock_gettime \
            __vdso_getcpu __vdso_gettimeofday __vdso_time \
            | sort)"
}

build_arm() {
    need "$acc"; need ld.lld; need "$astrip"; need readelf
    echo "vdso: building vdso-aarch64.so (aarch64-unknown-linux-gnu)"
    "$acc" --target=aarch64-unknown-linux-gnu -fuse-ld=lld $common \
        -Wl,--version-script="$here/vdso-aarch64.map" \
        -Wl,-soname,linux-vdso.so.1 -Wl,--build-id=none \
        -o "$out/vdso-aarch64.so" "$here/vdso-aarch64.S"
    "$astrip" --strip-debug --remove-section=.comment --remove-section=.note \
        "$out/vdso-aarch64.so"
    validate "$out/vdso-aarch64.so" "AArch64" "LINUX_2.6.39" \
        "$(printf '%s@@LINUX_2.6.39\n' __kernel_clock_getres __kernel_clock_gettime \
            __kernel_gettimeofday __kernel_rt_sigreturn | sort)"
}

case "$arch" in
    x86_64) build_x86 ;;
    aarch64) build_arm ;;
    all) build_x86; build_arm ;;
    *) echo "vdso: unknown architecture: $arch" >&2; exit 2 ;;
esac
