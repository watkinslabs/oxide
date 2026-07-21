#!/usr/bin/env bash
# Verify aggregate ARM mprotect tracing has no operation records unless detail is armed.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
base_id="arm-mprotect-summary-$$"
detail_id="arm-mprotect-detail-$$"
pages_id="arm-mprotect-pages-$$"
cleanup() {
    rm -rf "$repo/target/builds/$base_id" "$repo/target/builds/$detail_id" "$repo/target/builds/$pages_id"
}
trap cleanup EXIT

build() {
    local id="$1" feature="$2"
    (
        cd "$repo"
        cargo run -q -p xtask -- kernel --arch aarch64 --id "$id" --features "$feature"
    )
}

elf() {
    printf '%s/target/builds/%s/aarch64-unknown-oxide-kernel/release/oxide-aarch64\n' "$repo" "$1"
}

require_literal() {
    local image="$1" literal="$2"
    rg -a -F -q "$literal" "$image" || {
        echo "missing literal $literal in $image" >&2
        exit 1
    }
}

forbid_literal() {
    local image="$1" literal="$2"
    if rg -a -F -q "$literal" "$image"; then
        echo "unexpected literal $literal in $image" >&2
        exit 1
    fi
}

build "$base_id" debug-arm-mprotect
base_elf="$(elf "$base_id")"
test -f "$base_elf"
require_literal "$base_elf" "[ARM-MPROTECT] checkpoint retired-root="
require_literal "$base_elf" "[ARM-MPROTECT] failure root="
forbid_literal "$base_elf" "[ARM-MPROTECT] operation begin root="
forbid_literal "$base_elf" "[ARM-MPROTECT] operation end root="
forbid_literal "$base_elf" "[ARM-MPROTECT] page va="

build "$detail_id" debug-arm-mprotect-detail
detail_elf="$(elf "$detail_id")"
test -f "$detail_elf"
require_literal "$detail_elf" "[ARM-MPROTECT] checkpoint retired-root="
require_literal "$detail_elf" "[ARM-MPROTECT] failure root="
require_literal "$detail_elf" "[ARM-MPROTECT] operation begin root="
require_literal "$detail_elf" "[ARM-MPROTECT] operation end root="
require_literal "$detail_elf" "[ARM-MPROTECT] page va="

build "$pages_id" debug-arm-mprotect-pages
pages_elf="$(elf "$pages_id")"
test -f "$pages_elf"
require_literal "$pages_elf" "[ARM-MPROTECT] operation begin root="
require_literal "$pages_elf" "[ARM-MPROTECT] operation end root="
require_literal "$pages_elf" "[ARM-MPROTECT] page va="
echo "arm mprotect debug feature validation: PASS"
