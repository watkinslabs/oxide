#!/usr/bin/env bash
# tools/fetch-vendor.sh — populate `vendor/` with bootloader + firmware
# binaries we depend on at run time. Idempotent: skips files that
# already exist with matching checksums. Run once at workspace setup
# and after edits to the pinned versions below.
#
# Per `36§3` (multiboot2, x86_64) + `36§4` (UEFI / DTB, aarch64) + this
# repo's no-vendored-binaries-in-git policy (see vendor/README.md).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$REPO_ROOT/vendor"

# ---------------------------------------------------------------------------
# Pinned versions. Bump together with the corresponding sha256.
# ---------------------------------------------------------------------------

# OVMF pins name the firmware our boots are actually validated against.
# The upstream URL is a *rolling nightly* that no longer serves these
# bytes, so a fresh worktree cannot re-download them: the local cache
# below (seeded from any tree that already has a verified copy) is the
# real source. Until these are mirrored under our own ghcr.io / S3, the
# cache is what makes a new worktree reproducible.

OVMF_AA64_URL="https://retrage.github.io/edk2-nightly/bin/RELEASEAARCH64_QEMU_EFI.fd"
OVMF_AA64_SHA256="403fd8ae69c1c42764a383f0917cc249df2caeb06a789c9f0ca231b9427ef518"

# Shared across worktrees so one verified download serves every clone.
FIRMWARE_CACHE="${OXIDE_FIRMWARE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/oxide/firmware}"

# ---------------------------------------------------------------------------

mkdir -p "$VENDOR/firmware"

mkdir -p "$FIRMWARE_CACHE"
FAILED=""

# Quiet sha check — callers decide what a mismatch means.
sha_is() {
    local file="$1" expected="$2"
    [ -f "$file" ] || return 1
    [ "$(sha256sum "$file" | cut -d' ' -f1)" = "$expected" ]
}

# Resolve one artifact: existing file, then shared cache, then network.
# A drifted upstream is reported and recorded, never fatal mid-script —
# an unrelated later fetch (grub arm64-efi) must still run.
fetch() {
    local url="$1" dest="$2" sha="$3" label="$4"
    local cached="$FIRMWARE_CACHE/$label"

    if [ -z "$sha" ]; then
        echo "  ${label}: no pin set; sha256=$(sha256sum "$dest" | cut -d' ' -f1)"
        return 0
    fi

    if [ -f "$dest" ]; then
        if sha_is "$dest" "$sha"; then
            echo "  ${label}: present, sha256 ok"
            sha_is "$cached" "$sha" || cp -f "$dest" "$cached"   # seed cache
            return 0
        fi
        echo "  ${label}: present but sha256 mismatch (got $(sha256sum "$dest" | cut -d' ' -f1))" >&2
        rm -f "$dest"
    fi

    if sha_is "$cached" "$sha"; then
        cp -f "$cached" "$dest"
        echo "  ${label}: restored from cache, sha256 ok"
        return 0
    fi

    echo "  fetching ${label} ← ${url}"
    if curl -fL --retry 3 --retry-delay 2 -o "$dest" "$url" && sha_is "$dest" "$sha"; then
        echo "  ${label}: sha256 ok"
        cp -f "$dest" "$cached"
        return 0
    fi

    local got="(download failed)"
    [ -f "$dest" ] && got="$(sha256sum "$dest" | cut -d' ' -f1)"
    rm -f "$dest"
    echo "  ${label}: UNAVAILABLE — want ${sha}, upstream now serves ${got}" >&2
    echo "     The pinned URL is a rolling nightly and no longer serves the" >&2
    echo "     validated bytes. Copy a good one from a tree that has it:" >&2
    echo "       cp <good-tree>/vendor/firmware/${label} ${cached}" >&2
    FAILED="${FAILED} ${label}"
    return 0
}

# Both arches boot via GRUB (x86 multiboot2, arm EFI-stub `linux`). x86
# GRUB uses the host grub2-mkrescue; arm GRUB uses the vendored arm64-efi
# modules fetched below.

# ---------------------------------------------------------------------------
# OVMF firmware (EDK2 nightly snapshots)
# ---------------------------------------------------------------------------


echo "ovmf aarch64:"
fetch "$OVMF_AA64_URL"  "$VENDOR/firmware/ovmf-aarch64.fd" "$OVMF_AA64_SHA256" "ovmf-aarch64.fd"

# ---------------------------------------------------------------------------
# GRUB arm64-efi modules — the aarch64 boot path is GRUB EFI-stub
# `linux`. The host's GRUB is
# x86-only, so vendor the arm64-efi platform modules for `grub2-mkrescue
# -d vendor/grub/arm64-efi`. Delegated to fetch-grub.sh (Fedora RPM).
# ---------------------------------------------------------------------------
echo "grub arm64-efi:"
sh "$(dirname "$0")/fetch-grub.sh"

if [ -n "$FAILED" ]; then
    echo "fetch-vendor: FAILED —${FAILED}" >&2
    exit 1
fi

echo "vendor/ ready under $VENDOR (cache: $FIRMWARE_CACHE)"
