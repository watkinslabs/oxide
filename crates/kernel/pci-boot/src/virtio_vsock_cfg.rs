// virtio-vsock device-cfg + q1 notify-VA helpers, split out of
// `virtio_drv` to keep that file under the 1000-line cap (docs/08§7).
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
    (cid, true)
}

/// Install the virtio-vsock ring engine: fetch the per-arch HHDM offset
/// + hand the q0/q1 ring PAs + guest CID to drv-virtio-vsock (which
/// pre-posts RX buffers + installs the net::vsock TX hook). Returns true
/// on success. # C: O(RX ring depth)
#[allow(clippy::too_many_arguments)]
pub(super) fn install_vsock(
    q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64, q0_notify_va: u64, q0_size: u16,
    q1_desc_pa: u64, q1_driver_pa: u64, q1_device_pa: u64, q1_notify_va: u64, q1_size: u16,
    guest_cid: u64,
) -> bool {
    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    drv_virtio_vsock::install(
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, q0_size,
        q1_desc_pa, q1_driver_pa, q1_device_pa, q1_notify_va, q1_size,
        guest_cid, hhdm,
    )
}

/// Map the q1 notify window for virtio-vsock TX kicks. Returns the
/// kick VA, or 0 if the NOTIFY cap / BAR don't decode. No dummy frame
/// is posted (vsock sends real packets post-boot). # C: O(1)
pub(super) fn map_q1_notify(
    notify_cap: &virtio::VirtioPciCap,
    bars: &[pci::Bar],
    q1_notify_off: u16,
) -> u64 {
    let nbar_pa = match bars[notify_cap.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return 0,
    };
    if nbar_pa == 0 { return 0; }
    let nfy_pa = nbar_pa + notify_cap.offset as u64
        + (q1_notify_off as u64) * (notify_cap.notify_off_multiplier as u64);
    let n_page_pa = nfy_pa & !0xFFF;
    let n_page_off = nfy_pa - n_page_pa;
    // SAFETY: NOTIFY BAR PA decoded from device cap; bump VA private to virtio.
    let n_va = unsafe { map_mmio_pages(n_page_pa, 1) };
    n_va + n_page_off
}
