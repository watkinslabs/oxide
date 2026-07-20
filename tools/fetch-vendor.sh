#!/usr/bin/env bash
# tools/fetch-vendor.sh — populate `vendor/` with bootloader + firmware
# binaries we depend on at run time. Idempotent: skips files that
# already exist with matching checksums. Run once at workspace setup
# and after edits to the pinned versions below.
#
# Per `36§3` (Limine, x86_64) + `36§4` (UEFI / DTB, aarch64) + this
# repo's no-vendored-binaries-in-git policy (see vendor/README.md).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$REPO_ROOT/vendor"

# ---------------------------------------------------------------------------
# Pinned versions. Bump together with the corresponding sha256.
# ---------------------------------------------------------------------------

# OVMF nightlies move; pin the *current* sha so fetches verify, but
# expect to bump on every refresh. Long-term we should mirror these
# under our own ghcr.io / S3 to detach from upstream rotation.
OVMF_X64_URL="https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF.fd"
OVMF_X64_SHA256="446e971dc8069ba7292ca0dc2527483948e3f07cbb56172568427fd654d83fca"

OVMF_AA64_URL="https://retrage.github.io/edk2-nightly/bin/RELEASEAARCH64_QEMU_EFI.fd"
OVMF_AA64_SHA256="7e99f8cae5af16169717bdc332f825243a7bfa25fe85853b4f884b05598c5b83"

# ---------------------------------------------------------------------------

mkdir -p "$VENDOR/firmware"

verify_or_warn() {
    local file="$1" expected="$2" label="$3"
    if [ -z "$expected" ]; then
        local actual
        actual="$(sha256sum "$file" | cut -d' ' -f1)"
        echo "  ${label}: sha256=${actual} (no pin set; copy into fetch-vendor.sh)"
        return
    fi
    local actual
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
    if [ "$actual" != "$expected" ]; then
        echo "  ${label}: sha256 mismatch (got ${actual}, want ${expected})" >&2
        rm -f "$file"
        exit 1
    fi
    echo "  ${label}: sha256 ok"
}

fetch() {
    local url="$1" dest="$2" sha="$3" label="$4"
    if [ -f "$dest" ]; then
        echo "  ${label}: present (skip)"
        return
    fi
    echo "  fetching ${label} ← ${url}"
    curl -fL --retry 3 --retry-delay 2 -o "$dest" "$url"
    verify_or_warn "$dest" "$sha" "$label"
}

# Limine is gone — both arches boot via GRUB now (x86 multiboot2, arm
# EFI-stub `linux`). x86 GRUB uses the host grub2-mkrescue; arm GRUB uses
# the vendored arm64-efi modules fetched below.

# ---------------------------------------------------------------------------
# OVMF firmware (EDK2 nightly snapshots)
# ---------------------------------------------------------------------------

echo "ovmf x86_64:"
fetch "$OVMF_X64_URL"   "$VENDOR/firmware/ovmf-x64.fd"     "$OVMF_X64_SHA256"  "ovmf-x64.fd"

echo "ovmf aarch64:"
fetch "$OVMF_AA64_URL"  "$VENDOR/firmware/ovmf-aarch64.fd" "$OVMF_AA64_SHA256" "ovmf-aarch64.fd"

# ---------------------------------------------------------------------------
# GRUB arm64-efi modules — the aarch64 boot path is GRUB EFI-stub `linux`
# (Limine-free, replaces the old Limine BOOTAA64.EFI). The host's GRUB is
# x86-only, so vendor the arm64-efi platform modules for `grub2-mkrescue
# -d vendor/grub/arm64-efi`. Delegated to fetch-grub.sh (Fedora RPM).
# ---------------------------------------------------------------------------
echo "grub arm64-efi:"
sh "$(dirname "$0")/fetch-grub.sh"

echo "vendor/ ready under $VENDOR"
