# Vendor preflight, shared by every harness that boots a guest.
#
# `vendor/` holds fetched, gitignored boot artifacts, so a FRESH FEATURE
# WORKTREE has none. An arm boot then fails on missing arm64-efi GRUB modules
# before QEMU ever starts, and the harness reports it as "boot exited before
# UART became available" — which reads as a kernel fault and is not one. Lanes
# have lost runs to this repeatedly, and the fix kept landing in only the one
# script that lane happened to use: `boot-smoke.sh` grew a preflight while all
# three differential runners and every targeted smoke went without, so the same
# failure kept reappearing through a different entry point.
#
# Sourced, not executed. Callers set ARCH first, then call `vendor_preflight`.
# Nothing happens on x86, which needs no vendored boot artifacts.

# Absolute repository root, independent of the caller's working directory.
VENDOR_PREFLIGHT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Whether this tree has everything an ARM guest needs to reach its bootloader.
vendor_ready() {
    [ "${ARCH:-}" != arm ] || {
        [ -f "$VENDOR_PREFLIGHT_ROOT/vendor/grub/arm64-efi/modinfo.sh" ] \
            && [ -f "$VENDOR_PREFLIGHT_ROOT/vendor/grub/arm64-efi/linux.mod" ] \
            && [ -f "$VENDOR_PREFLIGHT_ROOT/vendor/grub/arm64-efi/archelp.mod" ] \
            && [ -f "$VENDOR_PREFLIGHT_ROOT/vendor/firmware/ovmf-aarch64.fd" ]
    }
}

# Fetch the vendored boot artifacts if this tree lacks them, and FAIL LOUDLY
# — with a message naming the real cause — rather than letting the boot fail
# somewhere that looks like kernel code. Locked, because sibling lanes fetch
# into the same tree concurrently.
vendor_preflight() {
    vendor_ready && return 0
    mkdir -p "$VENDOR_PREFLIGHT_ROOT/target"
    exec {VENDOR_LOCK_FD}>"$VENDOR_PREFLIGHT_ROOT/target/.vendor-fetch.lock"
    if ! flock "$VENDOR_LOCK_FD"; then
        echo "vendor-preflight: could not lock vendor preflight" >&2
        return 2
    fi
    echo "vendor-preflight: vendor/ incomplete in this tree — running tools/fetch-vendor.sh" >&2
    # Re-check under the lock: a sibling lane may have fetched while we waited.
    if ! vendor_ready && ! sh "$VENDOR_PREFLIGHT_ROOT/tools/fetch-vendor.sh" >&2; then
        echo "vendor-preflight: vendor fetch FAILED — the boot would fail on missing boot artifacts, NOT on kernel code" >&2
        return 2
    fi
    if ! vendor_ready; then
        echo "vendor-preflight: vendor fetch incomplete — required ARM GRUB/firmware artifacts still absent" >&2
        return 2
    fi
    flock -u "$VENDOR_LOCK_FD"
    exec {VENDOR_LOCK_FD}>&-
    return 0
}
