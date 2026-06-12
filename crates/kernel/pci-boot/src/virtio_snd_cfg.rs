// virtio-snd device-cfg harvest + install glue, split out of `virtio_drv`
// to keep that file under the 1000-line cap (docs/08§7). virtio_snd_config
// (docs/58§4, 16 bytes) = le32 jacks; le32 streams; le32 chmaps; le32
// controls at device-cfg offset 0. Read once at probe to size the PCM/jack
// tables; handed to drv-virtio-snd's CONTROLQ engine via `install_snd`.

use super::map_mmio_pages;

/// Harvest `(jacks, streams, chmaps, controls)` from the virtio-snd
/// device-cfg region (16 bytes @0). None if the DEVICE_CFG cap's BAR
/// doesn't decode.
/// # C: O(1) — one page map + four u32 MMIO reads
pub(super) fn harvest(
    devcfg_cap: &virtio::VirtioPciCap,
    bars: &[pci::Bar],
) -> Option<(u32, u32, u32, u32)> {
    let dbar_pa = match bars[devcfg_cap.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return None,
    };
    if dbar_pa == 0 { return None; }
    let d_pa = dbar_pa + devcfg_cap.offset as u64;
    let d_page_pa = d_pa & !0xFFF;
    let d_page_off = d_pa - d_page_pa;
    // SAFETY: device-cfg BAR PA decoded from the device cap; one-page window
    // covers the 16-byte virtio_snd_config at offset 0.
    let d_va = unsafe { map_mmio_pages(d_page_pa, 1) };
    let cfg_va = d_va + d_page_off;
    // SAFETY: cfg_va Device-attr-mapped above; four aligned u32 reads of the
    // virtio_snd_config fields within the one-page device-cfg window.
    let vals = unsafe {(
        core::ptr::read_volatile(cfg_va as *const u32),
        core::ptr::read_volatile((cfg_va + 4) as *const u32),
        core::ptr::read_volatile((cfg_va + 8) as *const u32),
        core::ptr::read_volatile((cfg_va + 12) as *const u32),
    )};
    Some(vals)
}

/// Install the virtio-snd CONTROLQ engine: fetch the per-arch HHDM offset +
/// hand the q0 ring PAs + config counts to drv-virtio-snd (which allocates
/// the control scratch frame and queries the PCM stream table). Returns the
/// probe result (stream split) for the boot line. # C: O(streams)
#[allow(clippy::too_many_arguments)]
pub(super) fn install_snd(
    q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64, q0_notify_va: u64, q0_size: u16,
    jacks: u32, streams: u32, chmaps: u32, controls: u32,
) -> Option<drv_virtio_snd::SndProbe> {
    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    drv_virtio_snd::install(drv_virtio_snd::SndInstall {
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, q0_size, hhdm,
        jacks, streams, chmaps, controls,
    })
}
