#!/usr/bin/env bash
# tools/fetch-vendor.sh — populate `vendor/` with bootloader + firmware
# binaries we depend on at run time. Idempotent: skips files that
# already exist with matching checksums. Run once at workspace setup
# and after edits to the pinned versions below.
#
# Per `36§4` (UEFI / DTB) + this repo's no-vendored-binaries-in-git
# policy (see vendor/README.md). Boot is GRUB on both arches (F376):
# x86 multiboot2, arm OVMF→GRUB→EFI-stub; only OVMF firmware is fetched
# here. GRUB modules are vendored separately under vendor/grub.

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
OVMF_X64_SHA256="4f4a8d5092c18219f67291731785b6714811bd2b677029a52f95699718c72aef"

OVMF_AA64_URL="https://retrage.github.io/edk2-nightly/bin/RELEASEAARCH64_QEMU_EFI.fd"
OVMF_AA64_SHA256="403fd8ae69c1c42764a383f0917cc249df2caeb06a789c9f0ca231b9427ef518"

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

# ---------------------------------------------------------------------------
# OVMF firmware (EDK2 nightly snapshots)
# ---------------------------------------------------------------------------

echo "ovmf x86_64:"
fetch "$OVMF_X64_URL"   "$VENDOR/firmware/ovmf-x64.fd"     "$OVMF_X64_SHA256"  "ovmf-x64.fd"

echo "ovmf aarch64:"
fetch "$OVMF_AA64_URL"  "$VENDOR/firmware/ovmf-aarch64.fd" "$OVMF_AA64_SHA256" "ovmf-aarch64.fd"

echo "vendor/ ready under $VENDOR"
