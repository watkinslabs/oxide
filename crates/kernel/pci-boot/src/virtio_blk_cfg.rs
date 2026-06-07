// virtio-blk device-cfg harvest (Stage 1), split out of `virtio_drv`
// to keep that file under the 1000-line cap. Reads `virtio_blk_config`
// (spec §5.2.4) through the DEVICE_CFG cap: capacity (le64 sectors,
// 512B units) @0, blk_size (le32) @20 iff VIRTIO_BLK_F_BLK_SIZE. The
// device serial is NOT in device-cfg (offset 24 is the topology block)
// — it's read by the engine via a GET_ID request after DRIVER_OK.

use super::map_mmio_pages;

/// Harvest `(capacity_sectors, blk_size, valid)` from the virtio-blk
/// device-cfg region. `valid=false` (defaults returned) if the cap's
/// BAR doesn't decode to a memory window — the caller must then skip
/// registration so ext4 never sees a zero-capacity phantom disk.
/// # C: O(1) — one page map + ~12 u8 MMIO reads
pub(super) fn harvest(
    devcfg_cap: &virtio::VirtioPciCap,
    bars: &[pci::Bar; 6],
    drv_features: u64,
) -> (u64, u32, bool) {
    let mut blk_size = virtio::VIRTIO_BLK_SECTOR_BYTES;
    let dbar_pa = match bars[devcfg_cap.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return (0, blk_size, false),
    };
    if dbar_pa == 0 { return (0, blk_size, false); }
    let d_pa = dbar_pa + devcfg_cap.offset as u64;
    let d_page_pa = d_pa & !0xFFF;
    let d_page_off = d_pa - d_page_pa;
    // SAFETY: device-cfg BAR PA decoded from the device cap; bump VA
    // private; one page covers virtio_blk_config (capacity@0..8,
    // blk_size@20).
    let d_va = unsafe { map_mmio_pages(d_page_pa, 1) };
    let cfg = d_va + d_page_off;

    let mut capb = [0u8; 8];
    for i in 0..8 {
        // SAFETY: cfg Device-attr window mapped above; aligned u8 read
        // of the le64 capacity within the blk-config page.
        capb[i] = unsafe { core::ptr::read_volatile((cfg + i as u64) as *const u8) };
    }
    let capacity = u64::from_le_bytes(capb);

    if drv_features & virtio::VIRTIO_BLK_F_BLK_SIZE != 0 {
        let mut bsb = [0u8; 4];
        for i in 0..4 {
            // SAFETY: cfg Device-attr window; u8 read at blk_size offset
            // 20 within the blk-config page.
            bsb[i] = unsafe {
                core::ptr::read_volatile(
                    (cfg + virtio::BLK_CFG_OFF_BLK_SIZE + i as u64) as *const u8)
            };
        }
        let bs = u32::from_le_bytes(bsb);
        if bs != 0 { blk_size = bs; }
    }

    (capacity, blk_size, true)
}

/// Hand the persistent queue-0 addresses + harvested device-cfg to the
/// virtio-blk engine, which reads the serial (GET_ID), builds a
/// `BlockDevice`, and registers it under a unique name.
/// # C: O(1) + registry O(N_disks)
#[allow(clippy::too_many_arguments)]
pub(super) fn register_blk(
    bus: u8, device: u8, function: u8,
    q0_desc_pa: u64, q0_avail_pa: u64, q0_used_pa: u64,
    q0_notify_va: u64, q0_size: u16, capacity: u64, blk_size: u32,
) {
    let _ = drv_virtio_blk::modern::init_blk(drv_virtio_blk::modern::BlkInit {
        bus, device, function,
        q0_desc_pa, q0_avail_pa, q0_used_pa, q0_notify_va,
        q0_size, capacity, blk_size,
    });
}
