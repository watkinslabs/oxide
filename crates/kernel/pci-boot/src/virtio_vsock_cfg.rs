// virtio-vsock device-cfg + install glue, split out of `virtio_drv` to keep
// that file under the 1000-line cap (docs/08§7).
// virtio_vsock_config (spec §5.10.4) is just a le64 guest_cid at
// device-cfg offset 0. The q1 notify window is mapped the same way the
// net TX path maps it, but with no warm-up frame (vsock posts real
// OP_* packets post-boot).

use super::map_mmio_pages;

/// Harvest `(guest_cid, valid)` from the virtio-vsock device-cfg region
/// (le64 @0). `valid=false` if the DEVICE_CFG cap's BAR doesn't decode.
/// # C: O(1) — one page map + one u64 MMIO read
pub(super) fn harvest_cid(
    devcfg_cap: &virtio::VirtioPciCap,
    bars: &[pci::Bar],
) -> (u64, bool) {
    let dbar_pa = match bars[devcfg_cap.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return (0, false),
    };
    if dbar_pa == 0 { return (0, false); }
    let d_pa = dbar_pa + devcfg_cap.offset as u64;
    let d_page_pa = d_pa & !0xFFF;
    let d_page_off = d_pa - d_page_pa;
    // SAFETY: device-cfg BAR PA decoded from device cap; one-page window
    // covers the 8-byte guest_cid at offset 0.
    let d_va = unsafe { map_mmio_pages(d_page_pa, 1) };
    let cid_va = d_va + d_page_off;
    // SAFETY: cid_va Device-attr-mapped above; aligned u64 read of
    // guest_cid within the one-page device-cfg window.
    let cid = unsafe { core::ptr::read_volatile(cid_va as *const u64) };
    // SAFETY: this was a temporary one-page device-cfg mapping used only for
    // the harvest read above; no runtime driver keeps this VA.
    unsafe { mmio_map::unmap_pages(d_va, 1); }
    (cid, true)
}

/// Install the virtio-vsock ring engine: hand typed q0/q1 resources + guest
/// CID to drv-virtio-vsock, which pre-posts RX buffers and installs the
/// net::vsock TX hook. Returns true on success. # C: O(RX ring depth)
pub(super) fn install_vsock(
    device_key: u32,
    resources: virtio::VirtioResources,
    guest_cid: u64,
) -> bool {
    drv_virtio_vsock::install(device_key, resources, guest_cid)
}
