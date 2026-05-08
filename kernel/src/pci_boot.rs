// PCI enumeration boot helper — wraps `pci::enumerate` with per-arch
// `ConfigSpaceReader` selection (x86 LegacyPci CF8/CFC, aarch64
// EcamPci MMIO seeded by `device_map_smoke_arm`). Split out of
// `lib.rs` to keep that file under the 1000-line cap (08§7).

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};
use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
#[cfg(target_arch = "aarch64")]
use hal_aarch64::mmu_ops::ArmMmu;
#[cfg(target_arch = "x86_64")]
use hal_x86_64::mmu_ops::X86Mmu;

/// Kernel VA bump-allocator base for virtio BAR mappings. Disjoint
/// from `KERNEL_DEVICE_BASE` (low-32 PA alias) and `ECAM_BUS0_VA`.
const VIRTIO_BAR_VA_BASE: u64 = 0xffff_fd00_0000_0000;
static VIRTIO_BAR_VA_NEXT: AtomicU64 = AtomicU64::new(VIRTIO_BAR_VA_BASE);

fn device_flags() -> PageFlags {
    PageFlags::READ | PageFlags::WRITE | PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH
}

/// Map `n_pages` of MMIO at PA `pa` (4K-aligned) into kernel VA at
/// the next free virtio-BAR slot. Returns the base VA.
/// # SAFETY: caller asserts (a) `pa` names a real device region the
/// kernel exclusively owns, (b) PMM ready + single-CPU + IRQs masked,
/// (c) `pa` is 4K-aligned. Used only at boot for virtio probing.
/// # C: O(n_pages × walk depth)
unsafe fn map_mmio_pages(pa: u64, n_pages: u64) -> u64 {
    let bytes = n_pages * 0x1000;
    let base = VIRTIO_BAR_VA_NEXT.fetch_add(bytes, Ordering::AcqRel);
    for i in 0..n_pages {
        let va = base + i * 0x1000;
        let pa_i = pa + i * 0x1000;
        // SAFETY: per fn contract; kernel-half VA is private to the
        // bump allocator above; map() splices a Device-attr leaf.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            <X86Mmu as MmuOps>::map(Va(va), Pa(pa_i), device_flags(), PageSize::P4K);
            #[cfg(target_arch = "aarch64")]
            <ArmMmu as MmuOps>::map(Va(va), Pa(pa_i), device_flags(), PageSize::P4K);
        }
    }
    base
}

/// Outcome of one virtio-pci modern probe. All side-effect work
/// (cmd-reg write, BAR mapping, status state machine, feature
/// negotiation, queue size scan, queue 0 ring program + DRIVER_OK)
/// runs unconditionally; only the trace logging consumes this struct
/// under `debug_boot!`.
struct VirtioProbe {
    cmd_orig: u16,
    cmd_new:  u16,
    cfg_va:   u64,
    dev_features: u64,
    drv_features: u64,
    post_status: u32,
    features_ok: bool,
    msix_cfg:    u16,
    num_queues:  u16,
    /// Up to 8 (queue_idx, queue_size) entries seen in the scan.
    queues: [(u16, u16); 8],
    queues_len: usize,
    /// Queue-0 ring frame PAs after F25 setup (0 = not allocated).
    q0_desc_pa:   u64,
    q0_driver_pa: u64,
    q0_device_pa: u64,
    /// Final status byte after writing DRIVER_OK + re-reading.
    final_status: u8,
    /// F26: queue-0 notify offset (raw value from queue_notify_off
    /// at common cfg +0x1E; multiply by notify_off_multiplier and
    /// add to NOTIFY BAR base to get the kick address).
    q0_notify_off: u16,
    /// F26: kernel VA the NOTIFY BAR window was mapped at, plus the
    /// per-queue offset baked in. 0 = notify path not brought up.
    q0_notify_va:  u64,
    /// F26: status byte after writing queue_index=0 to the notify
    /// address. Should remain 0x0f (no FAILED transition).
    post_notify_status: u8,
    /// F28: avail.idx written by the driver (1 = one descriptor posted).
    avail_idx_posted: u16,
    /// F28: used.idx read after the kick + brief wait.
    used_idx_observed: u16,
    /// F29: ISR status byte read post-kick. Bit 0 = queue interrupt,
    /// bit 1 = config interrupt. Reading clears the register.
    isr_status: u8,
    /// F30: 20-byte device-ID string from VIRTIO_BLK_T_GET_ID, or
    /// zeros if not a virtio-blk device or the request didn't complete.
    blk_id: [u8; 20],
    /// F30: virtio-blk request status byte. 0=OK, 1=IOERR, 2=UNSUPP,
    /// 0xFF=request not issued / not completed.
    blk_status: u8,
}

/// Drive one modern virtio-pci device through FEATURES_OK and
/// scan its queue layout. Returns Some(probe) on success.
/// # SAFETY: caller is the boot path; PMM ready; single-CPU; IRQs masked.
/// # C: O(BAR pages mapped + ~num_queues u32 reads)
fn virtio_init_arch(d: &pci::PciDevice) -> Option<VirtioProbe> {
    if !virtio::is_modern(d.vendor_id, d.device_id) { return None; }
    let bdf = d.bdf;

    // Re-walk caps + decode virtio cfgs + decode BARs.
    let (vcaps, bars) = {
        #[cfg(target_arch = "x86_64")]
        {
            let r = hal_x86_64::pci::LegacyPci;
            let c = pci::capabilities(&r, bdf);
            let v = virtio::decode_all(&r, bdf, &c);
            let b = pci::decode_bars(&r, bdf);
            (v, b)
        }
        #[cfg(target_arch = "aarch64")]
        {
            match hal_aarch64::pci::EcamPci::from_published() {
                Some(r) => {
                    let c = pci::capabilities(&r, bdf);
                    let v = virtio::decode_all(&r, bdf, &c);
                    let b = pci::decode_bars(&r, bdf);
                    (v, b)
                }
                None => return None,
            }
        }
    };

    // Enable Memory + BusMaster in the PCI command reg (UEFI on QEMU
    // virt leaves Memory bit OFF — confirmed by F22 boot trace).
    let cmd_orig = {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04) }
        #[cfg(target_arch = "aarch64")]
        { match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04),
            None => return None,
        } }
    };
    let cmd_new = (cmd_orig & 0xFFFF_0000) | ((cmd_orig & 0xFFFF) | 0x0006);
    if cmd_new != cmd_orig {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, cmd_new); }
        #[cfg(target_arch = "aarch64")]
        { if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, cmd_new);
        } }
    }

    // Locate COMMON cfg + map the BAR page.
    let common = vcaps.find(virtio::VIRTIO_PCI_CAP_COMMON_CFG)?;
    let bar_pa = match bars[common.bar as usize] {
        pci::Bar::Mem32 { base, .. } => base as u64,
        pci::Bar::Mem64 { base, .. } => base,
        _ => return None,
    };
    let common_pa = bar_pa + common.offset as u64;
    let page_pa = common_pa & !0xFFF;
    let page_off = (common_pa - page_pa) as u64;
    // SAFETY: BAR PA decoded from device BAR reg; bump VA is exclusive.
    let base_va = unsafe { map_mmio_pages(page_pa, 1) };
    let cfg_va = base_va + page_off;

    // u32 volatile R/W over the Device-attr MMIO window.
    let r32 = |off: u64| -> u32 {
        // SAFETY: cfg_va Device-attr mapped; off < 0x1000.
        unsafe { core::ptr::read_volatile((cfg_va + off) as *const u32) }
    };
    let w32 = |off: u64, v: u32| {
        // SAFETY: same window; writes drive device per spec.
        unsafe { core::ptr::write_volatile((cfg_va + off) as *mut u32, v); }
    };

    // Spec §3.1.1 driver init sequence.
    let st = |s: u8| -> u32 { s as u32 };
    w32(0x14, st(0));                                              // reset
    let _ = r32(0x14);
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE));
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
               | virtio::VIRTIO_STATUS_DRIVER));

    // Feature negotiation (insist on VIRTIO_F_VERSION_1, bit 32).
    w32(0x00, 0); let dev_feat_lo = r32(0x04);
    w32(0x00, 1); let dev_feat_hi = r32(0x04);
    let dev_features: u64 = ((dev_feat_hi as u64) << 32) | (dev_feat_lo as u64);
    let drv_features: u64 = dev_features & virtio::VIRTIO_F_VERSION_1;
    w32(0x08, 1); w32(0x0C, (drv_features >> 32) as u32);
    w32(0x08, 0); w32(0x0C, (drv_features & 0xFFFF_FFFF) as u32);
    w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
               | virtio::VIRTIO_STATUS_DRIVER
               | virtio::VIRTIO_STATUS_FEATURES_OK));

    let post_status = r32(0x14) & 0xFF;
    let features_ok = post_status & virtio::VIRTIO_STATUS_FEATURES_OK as u32 != 0;

    let w_msix_nq = r32(0x10);
    let msix_cfg   = (w_msix_nq & 0xFFFF) as u16;
    let num_queues = (w_msix_nq >> 16) as u16;

    // Queue scan: iterate queue_select 0..min(num_queues, 8) reading
    // queue_size at +0x18. queue_size==0 means the queue is disabled
    // (per spec). queue_select sits in the high u16 of the same dword
    // as device_status; preserve status when writing.
    let mut queues = [(0u16, 0u16); 8];
    let mut queues_len = 0usize;
    let cap = if num_queues == 0 || num_queues > 8 { 8 } else { num_queues } as u16;
    for qi in 0..cap {
        // Preserve status low byte; queue_select is bits 16..31.
        let qs_word = (post_status & 0xFF) | ((qi as u32) << 16);
        w32(0x14, qs_word);
        let qs_data = r32(0x18);
        let queue_size = (qs_data & 0xFFFF) as u16;
        queues[queues_len] = (qi, queue_size);
        queues_len += 1;
        if queue_size == 0 { break; }
    }

    // F26: capture queue-0 notify_off before any further state writes.
    // queue_notify_off is the high u16 of the dword at +0x1C.
    let q0_notify_off = (r32(0x1C) >> 16) as u16;

    // F25: program queue 0 if the device exposed one with a non-zero size.
    let q0_size = if queues_len > 0 { queues[0].1 } else { 0 };
    let (q0_desc_pa, q0_driver_pa, q0_device_pa, final_status) = if q0_size != 0 && features_ok {
        let pa_desc   = crate::pmm_setup::alloc_one_frame().unwrap_or(0);
        let pa_driver = crate::pmm_setup::alloc_one_frame().unwrap_or(0);
        let pa_device = crate::pmm_setup::alloc_one_frame().unwrap_or(0);
        if pa_desc != 0 && pa_driver != 0 && pa_device != 0 {
            // F27: zero the 3 ring frames via HHDM BEFORE programming
            // queue_enable so the device sees deterministic ring state.
            // PMM doesn't guarantee zero-init.
            let hhdm = {
                #[cfg(target_arch = "x86_64")]
                { hal_x86_64::mmu_ops::hhdm_offset() }
                #[cfg(target_arch = "aarch64")]
                { hal_aarch64::mmu_ops::hhdm_offset() }
            };
            if hhdm != 0 {
                for &pa in &[pa_desc, pa_driver, pa_device] {
                    let va = hhdm.wrapping_add(pa) as *mut u64;
                    // SAFETY: HHDM covers all RAM PMM hands out;
                    // single-CPU pre-init; we own these freshly-allocated
                    // frames; aligned u64 stores within a 4 KiB page.
                    unsafe {
                        for i in 0..(0x1000 / 8) {
                            core::ptr::write_volatile(va.add(i), 0);
                        }
                    }
                }
            }
            // Re-select queue 0 (queue_select sits in upper u16 of 0x14;
            // status low byte is sticky as device_status, preserve it).
            let qs0 = (post_status & 0xFF) | (0u32 << 16);
            w32(0x14, qs0);
            // queue_size at 0x18 (low u16) — leave as-is. queue_msix_vector
            // at 0x1A — leave 0xFFFF default for now (no MSI-X bound; F26).
            // queue_enable at 0x1C (low u16); queue_notify_off at 0x1E.
            // queue_desc le64 at +0x20:
            w32(0x20, (pa_desc & 0xFFFF_FFFF) as u32);
            w32(0x24, (pa_desc >> 32) as u32);
            // queue_driver (avail) le64 at +0x28:
            w32(0x28, (pa_driver & 0xFFFF_FFFF) as u32);
            w32(0x2C, (pa_driver >> 32) as u32);
            // queue_device (used) le64 at +0x30:
            w32(0x30, (pa_device & 0xFFFF_FFFF) as u32);
            w32(0x34, (pa_device >> 32) as u32);
            // queue_enable=1 (low u16 of dword at 0x1C; preserve high
            // u16 = queue_notify_off which is RO).
            let qen_word = r32(0x1C) & 0xFFFF_0000;
            w32(0x1C, qen_word | 0x0001);

            // DRIVER_OK
            w32(0x14, st(virtio::VIRTIO_STATUS_ACKNOWLEDGE
                       | virtio::VIRTIO_STATUS_DRIVER
                       | virtio::VIRTIO_STATUS_FEATURES_OK
                       | virtio::VIRTIO_STATUS_DRIVER_OK));
            let final_status = (r32(0x14) & 0xFF) as u8;
            (pa_desc, pa_driver, pa_device, final_status)
        } else {
            (0, 0, 0, post_status as u8)
        }
    } else {
        (0, 0, 0, post_status as u8)
    };
    // F30: for virtio-blk (transitional 0x1001 or modern 0x1042),
    // issue a VIRTIO_BLK_T_GET_ID request: header (16B) + data (20B) +
    // status (1B) in a 3-descriptor chain. Returns the device-id string
    // — a real DMA roundtrip without needing IRQs.
    let mut blk_id = [0u8; 20];
    let mut blk_status: u8 = 0xFF;
    let is_virtio_blk = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1001 || d.device_id == 0x1042);

    // F28: for virtio-net (transitional 0x1000 or modern 0x1041),
    // post one RX buffer descriptor on queue 0 and bump avail.idx
    // before kicking. For other devices the queue stays empty so the
    // kick is a no-op nudge.
    let mut avail_idx_posted = 0u16;
    let is_virtio_net = d.vendor_id == 0x1AF4
        && (d.device_id == 0x1000 || d.device_id == 0x1041);
    if is_virtio_blk && q0_desc_pa != 0 && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if let Some(buf_pa) = crate::pmm_setup::alloc_one_frame() {
            if hhdm != 0 {
                let buf_va = hhdm.wrapping_add(buf_pa) as *mut u8;
                // SAFETY: HHDM-mapped frame; aligned writes within 4 KiB.
                unsafe {
                    // Zero the buf first.
                    for i in 0..0x1000usize { core::ptr::write_volatile(buf_va.add(i), 0); }
                    // Header at +0x000: type=8 (VIRTIO_BLK_T_GET_ID), reserved=0, sector=0
                    core::ptr::write_volatile(buf_va.add(0) as *mut u32, 8);
                    // Pre-fill status byte at +0x200 with sentinel 0xFF.
                    core::ptr::write_volatile(buf_va.add(0x200), 0xFFu8);
                }
                // 3 descriptors at desc table:
                //   d0: { addr=buf+0x000, len=16, flags=NEXT(1),     next=1 }
                //   d1: { addr=buf+0x100, len=20, flags=WRITE|NEXT(3), next=2 }
                //   d2: { addr=buf+0x200, len= 1, flags=WRITE(2),     next=0 }
                let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u64;
                // SAFETY: HHDM-mapped virtio queue-0 descriptor table; aligned u64 stores within the frame the driver owns.
                unsafe {
                    // Descriptor 0
                    core::ptr::write_volatile(desc0.add(0), buf_pa);
                    let d0_lo = 16u64;
                    let d0_flags = (virtio::VRING_DESC_F_NEXT as u64) << 32;
                    let d0_next = 1u64 << 48;
                    core::ptr::write_volatile(desc0.add(1), d0_lo | d0_flags | d0_next);
                    // Descriptor 1
                    core::ptr::write_volatile(desc0.add(2), buf_pa + 0x100);
                    let d1_lo = 20u64;
                    let d1_flags = ((virtio::VRING_DESC_F_NEXT
                                   | virtio::VRING_DESC_F_WRITE) as u64) << 32;
                    let d1_next = 2u64 << 48;
                    core::ptr::write_volatile(desc0.add(3), d1_lo | d1_flags | d1_next);
                    // Descriptor 2
                    core::ptr::write_volatile(desc0.add(4), buf_pa + 0x200);
                    let d2_lo = 1u64;
                    let d2_flags = (virtio::VRING_DESC_F_WRITE as u64) << 32;
                    core::ptr::write_volatile(desc0.add(5), d2_lo | d2_flags);
                }
                // avail.ring[0] = 0; avail.idx = 1.
                let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
                // SAFETY: HHDM-mapped virtio queue-0 avail ring; aligned u16 stores within the driver-owned frame.
                unsafe {
                    core::ptr::write_volatile(avail.add(2), 0u16); // ring[0]
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // SAFETY: same ring; idx at u16 offset 1.
                unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                avail_idx_posted = 1;
            }
        }
    } else if is_virtio_net && q0_desc_pa != 0 && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if let Some(rx_pa) = crate::pmm_setup::alloc_one_frame() {
            if hhdm != 0 {
                // Descriptor[0]: { addr=rx_pa; len=2048; flags=WRITE(2); next=0 }
                let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *mut u64;
                // SAFETY: HHDM-mapped, freshly-allocated frame, single-CPU.
                unsafe {
                    core::ptr::write_volatile(desc0, rx_pa);
                    // len=2048 (low 32) | flags=WRITE(2) << 32 | next=0 << 48
                    let lo32 = 2048u32 as u64;
                    let flags_next = (virtio::VRING_DESC_F_WRITE as u64) << 32;
                    core::ptr::write_volatile(desc0.add(1), lo32 | flags_next);
                }
                // avail.ring[0] = 0 at driver_pa+0x04
                let avail = (hhdm.wrapping_add(q0_driver_pa)) as *mut u16;
                // SAFETY: same frame, ring[0] at byte +4 = u16 offset 2.
                unsafe {
                    core::ptr::write_volatile(avail.add(2), 0u16);
                }
                // Memory barrier so the descriptor + ring writes are
                // observable before avail.idx bump.
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                // avail.idx = 1 at driver_pa+0x02 (u16 offset 1).
                // SAFETY: HHDM-mapped avail ring as above; this u16 store at idx publishes the descriptor we just wrote.
                unsafe { core::ptr::write_volatile(avail.add(1), 1u16); }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                avail_idx_posted = 1;
            }
        }
    }

    // F26: kick the notify register for queue 0. Notify address per
    // Virtio 1.2 §4.1.4.4:
    //   notify_pa = NOTIFY_BAR_pa + notify_cap.offset + qoff * notify_mult
    // where qoff = the queue_notify_off captured above.
    let (q0_notify_va, post_notify_status) = if final_status & virtio::VIRTIO_STATUS_FAILED == 0
        && (final_status & virtio::VIRTIO_STATUS_DRIVER_OK) != 0
    {
        if let Some(notify_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_NOTIFY_CFG) {
            let nbar_pa = match bars[notify_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if nbar_pa != 0 {
                let nfy_pa = nbar_pa + notify_cap.offset as u64
                           + (q0_notify_off as u64) * (notify_cap.notify_off_multiplier as u64);
                let n_page_pa = nfy_pa & !0xFFF;
                let n_page_off = nfy_pa - n_page_pa;
                // SAFETY: NOTIFY BAR PA decoded from device cap; bump VA private.
                let n_va = unsafe { map_mmio_pages(n_page_pa, 1) };
                let kick_va = n_va + n_page_off;
                // Write queue index 0 as a u16 to the notify address.
                // SAFETY: kick_va Device-attr; aligned u16 write.
                unsafe { core::ptr::write_volatile(kick_va as *mut u16, 0u16); }
                // Brief observation window for any device-driven RX
                // completion (QEMU user-net delivers nothing without
                // packets, so used.idx will normally stay 0).
                for _ in 0..1_000_000 { core::hint::spin_loop(); }
                let st = (r32(0x14) & 0xFF) as u8;
                (kick_va, st)
            } else {
                (0u64, final_status)
            }
        } else {
            (0u64, final_status)
        }
    } else {
        (0u64, final_status)
    };

    // F29: locate ISR cap, map its BAR page, and read the ISR byte
    // post-kick. Per Virtio 1.2 §4.1.4.5: ISR is a 1-byte read-to-clear
    // register; bit 0 = queue interrupt, bit 1 = config-change
    // interrupt. With MSI-X unbound the device would normally route via
    // INTx; we're not catching those yet but the ISR poll lets us see
    // whether the device attempted notification.
    let isr_status = if avail_idx_posted > 0 {
        if let Some(isr_cap) = vcaps.find(virtio::VIRTIO_PCI_CAP_ISR_CFG) {
            let ibar_pa = match bars[isr_cap.bar as usize] {
                pci::Bar::Mem32 { base, .. } => base as u64,
                pci::Bar::Mem64 { base, .. } => base,
                _ => 0,
            };
            if ibar_pa != 0 {
                let isr_pa = ibar_pa + isr_cap.offset as u64;
                let i_page_pa = isr_pa & !0xFFF;
                let i_page_off = isr_pa - i_page_pa;
                // SAFETY: ISR BAR PA decoded from device cap; bump VA private.
                let i_va = unsafe { map_mmio_pages(i_page_pa, 1) };
                let isr_va = i_va + i_page_off;
                // SAFETY: isr_va Device-attr; aligned u8 read clears it.
                unsafe { core::ptr::read_volatile(isr_va as *const u8) }
            } else { 0 }
        } else { 0 }
    } else { 0 };

    // F30: harvest virtio-blk GET_ID result if we issued one. The data
    // descriptor's buffer pa = q0_desc_pa is encoded in desc[2*1+0] but
    // we already know it's `buf_pa+0x100`; rather than read the desc
    // back, walk the used ring to find the chain head, then dereference.
    if is_virtio_blk && avail_idx_posted > 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if hhdm != 0 {
            // Read used.idx at q0_device_pa+0x02 to confirm completion;
            // used.ring[0].id is at +0x04..+0x08 (le32 = chain head idx),
            // which we can use to recover the buffer PA via desc table.
            let used = (hhdm.wrapping_add(q0_device_pa)) as *const u16;
            // SAFETY: HHDM-mapped virtio queue-0 used ring; aligned u16 load at the idx field.
            let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
            if uidx > 0 {
                // descriptor-table is HHDM-mapped at q0_desc_pa
                let desc0 = (hhdm.wrapping_add(q0_desc_pa)) as *const u64;
                // SAFETY: HHDM-mapped virtio queue-0 descriptor table; aligned u64 load of the chain head's addr field.
                let d0_addr = unsafe { core::ptr::read_volatile(desc0.add(0)) };
                let buf_pa = d0_addr; // descriptor 0's addr is buf_pa + 0
                let buf_va = hhdm.wrapping_add(buf_pa) as *const u8;
                // SAFETY: HHDM-mapped data buf within the same page.
                unsafe {
                    for i in 0..20 {
                        blk_id[i] = core::ptr::read_volatile(buf_va.add(0x100 + i));
                    }
                    blk_status = core::ptr::read_volatile(buf_va.add(0x200));
                }
            }
        }
    }

    // F28: read used.idx after the kick.
    let used_idx_observed = if avail_idx_posted > 0 && q0_device_pa != 0 {
        let hhdm = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::mmu_ops::hhdm_offset() }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::mmu_ops::hhdm_offset() }
        };
        if hhdm != 0 {
            let used = (hhdm.wrapping_add(q0_device_pa)) as *const u16;
            // used.idx at +0x02 (u16 offset 1).
            // SAFETY: HHDM-mapped frame; aligned u16 load.
            unsafe { core::ptr::read_volatile(used.add(1)) }
        } else { 0 }
    } else { 0 };

    Some(VirtioProbe {
        cmd_orig: (cmd_orig & 0xFFFF) as u16,
        cmd_new:  (cmd_new  & 0xFFFF) as u16,
        cfg_va,
        dev_features,
        drv_features,
        post_status,
        features_ok,
        msix_cfg,
        num_queues,
        queues,
        queues_len,
        q0_desc_pa,
        q0_driver_pa,
        q0_device_pa,
        final_status,
        q0_notify_off,
        q0_notify_va,
        post_notify_status,
        avail_idx_posted,
        used_idx_observed,
        isr_status,
        blk_id,
        blk_status,
    })
}

/// Drive one modern virtio-pci device + emit `[INFO] virtio-cfg ...`
/// + per-queue `[INFO] virtio-q ...` lines under `debug-boot`.
/// Side-effect work runs unconditionally; only the trace is gated.
/// # C: O(BAR pages mapped + ~num_queues u32 reads)
fn virtio_probe_arch(d: &pci::PciDevice) {
    let p = match virtio_init_arch(d) { Some(p) => p, None => return };
    let bdf = d.bdf;
    debug_boot! {
        klog::write_raw(b"[INFO]  pci-cmd ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" was=");
        klog::write_hex_u64(p.cmd_orig as u64);
        klog::write_raw(b" now=");
        klog::write_hex_u64(p.cmd_new as u64);
        klog::write_raw(b"\n");

        klog::write_raw(b"[INFO]  virtio-cfg ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" common-va=");
        klog::write_hex_u64(p.cfg_va);
        klog::write_raw(b" feat=");
        klog::write_hex_u64(p.dev_features);
        klog::write_raw(b" drv_feat=");
        klog::write_hex_u64(p.drv_features);
        klog::write_raw(b" status=");
        klog::write_hex_u64(p.post_status as u64);
        klog::write_raw(b" features_ok=");
        klog::write_dec_u64(p.features_ok as u64);
        klog::write_raw(b" num_queues=");
        klog::write_dec_u64(p.num_queues as u64);
        klog::write_raw(b" msix_cfg=");
        klog::write_hex_u64(p.msix_cfg as u64);
        klog::write_raw(b"\n");

        for i in 0..p.queues_len {
            let (qi, qsz) = p.queues[i];
            klog::write_raw(b"[INFO]  virtio-q ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" idx=");
            klog::write_dec_u64(qi as u64);
            klog::write_raw(b" size=");
            klog::write_dec_u64(qsz as u64);
            klog::write_raw(b"\n");
        }
        if p.blk_status != 0xFF {
            klog::write_raw(b"[INFO]  virtio-blk-id ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" status=");
            klog::write_hex_u64(p.blk_status as u64);
            klog::write_raw(b" id=\"");
            // Render printable bytes; replace non-printables with '.'
            let mut buf = [b'.'; 20];
            for i in 0..20 {
                let b = p.blk_id[i];
                buf[i] = if b >= 0x20 && b < 0x7f { b } else if b == 0 { b'.' } else { b'?' };
            }
            klog::write_raw(&buf);
            klog::write_raw(b"\"\n");
        }
        if p.avail_idx_posted > 0 {
            klog::write_raw(b"[INFO]  virtio-rx-post ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" avail_idx=");
            klog::write_dec_u64(p.avail_idx_posted as u64);
            klog::write_raw(b" used_idx=");
            klog::write_dec_u64(p.used_idx_observed as u64);
            klog::write_raw(b" isr=");
            klog::write_hex_u64(p.isr_status as u64);
            klog::write_raw(b"\n");
        }
        if p.q0_notify_va != 0 {
            klog::write_raw(b"[INFO]  virtio-notify ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" q=0 off=");
            klog::write_hex_u64(p.q0_notify_off as u64);
            klog::write_raw(b" va=");
            klog::write_hex_u64(p.q0_notify_va);
            klog::write_raw(b" post_status=");
            klog::write_hex_u64(p.post_notify_status as u64);
            klog::write_raw(b"\n");
        }
        if p.q0_desc_pa != 0 {
            klog::write_raw(b"[INFO]  virtio-q0-prog ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" desc_pa=");
            klog::write_hex_u64(p.q0_desc_pa);
            klog::write_raw(b" driver_pa=");
            klog::write_hex_u64(p.q0_driver_pa);
            klog::write_raw(b" device_pa=");
            klog::write_hex_u64(p.q0_device_pa);
            klog::write_raw(b" final_status=");
            klog::write_hex_u64(p.final_status as u64);
            klog::write_raw(b"\n");
        }
    }
}

/// Emit one `[INFO] pci-bar <bdf> N <kind>=...` line per programmed BAR.
/// # C: O(1) — at most 6 BARs.
fn bar_dump_arch(bdf: pci::Bdf) {
    debug_boot! {
        let bars = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
                pci::decode_bars(&r, bdf)
            }
            #[cfg(target_arch = "aarch64")]
            {
                match hal_aarch64::pci::EcamPci::from_published() {
                    Some(r) => pci::decode_bars(&r, bdf),
                    None    => [pci::Bar::None; 6],
                }
            }
        };
        for (i, b) in bars.iter().enumerate() {
            match *b {
                pci::Bar::None | pci::Bar::HighHalfConsumed => continue,
                pci::Bar::Io { port } => {
                    klog::write_raw(b"[INFO]  pci-bar ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" b");
                    klog::write_dec_u64(i as u64);
                    klog::write_raw(b" io=");
                    klog::write_hex_u64(port as u64);
                    klog::write_raw(b"\n");
                }
                pci::Bar::Mem32 { base, prefetch } => {
                    klog::write_raw(b"[INFO]  pci-bar ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" b");
                    klog::write_dec_u64(i as u64);
                    klog::write_raw(b" mem32=");
                    klog::write_hex_u64(base as u64);
                    if prefetch { klog::write_raw(b" pf"); }
                    klog::write_raw(b"\n");
                }
                pci::Bar::Mem64 { base, prefetch } => {
                    klog::write_raw(b"[INFO]  pci-bar ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" b");
                    klog::write_dec_u64(i as u64);
                    klog::write_raw(b" mem64=");
                    klog::write_hex_u64(base);
                    if prefetch { klog::write_raw(b" pf"); }
                    klog::write_raw(b"\n");
                }
            }
        }
    }
}

/// Per-arch wrapper that walks the capability list for one BDF and
/// emits `[INFO] pci-cap ... id=...` lines. For modern virtio devices
/// (vendor=0x1AF4, device>=0x1040) it also decodes each vendor cap and
/// emits a `[INFO] virtio-cap ...` line per cfg_type.
/// # C: O(N_caps) — typical N is 1–6.
fn cap_dump_arch(d: &pci::PciDevice) {
    let bdf = d.bdf;
    debug_boot! {
        let caps = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
                pci::capabilities(&r, bdf)
            }
            #[cfg(target_arch = "aarch64")]
            {
                match hal_aarch64::pci::EcamPci::from_published() {
                    Some(r) => pci::capabilities(&r, bdf),
                    None    => pci::heapless_caps::CapVec::new(),
                }
            }
        };
        for c in caps.iter() {
            klog::write_raw(b"[INFO]  pci-cap ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" id=");
            klog::write_hex_u64(c.id as u64);
            klog::write_raw(b" off=");
            klog::write_hex_u64(c.cfg_off as u64);
            klog::write_raw(b"\n");
            // F32: decode the MSI-X cap header inline so the trace
            // reports table_size + BIR + offsets per device.
            if c.id == pci::CAP_ID_MSIX {
                let mx = {
                    #[cfg(target_arch = "x86_64")]
                    {
                        let r = hal_x86_64::pci::LegacyPci;
                        pci::decode_msix_cap(&r, bdf, c.cfg_off)
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        match hal_aarch64::pci::EcamPci::from_published() {
                            Some(r) => pci::decode_msix_cap(&r, bdf, c.cfg_off),
                            None => None,
                        }
                    }
                };
                if let Some(m) = mx {
                    klog::write_raw(b"[INFO]  msix ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" enable=");
                    klog::write_dec_u64(m.enabled as u64);
                    klog::write_raw(b" fn_mask=");
                    klog::write_dec_u64(m.function_mask as u64);
                    klog::write_raw(b" n=");
                    klog::write_dec_u64(m.table_size as u64);
                    klog::write_raw(b" tbl_bir=");
                    klog::write_dec_u64(m.table_bir as u64);
                    klog::write_raw(b" tbl_off=");
                    klog::write_hex_u64(m.table_offset as u64);
                    klog::write_raw(b" pba_bir=");
                    klog::write_dec_u64(m.pba_bir as u64);
                    klog::write_raw(b" pba_off=");
                    klog::write_hex_u64(m.pba_offset as u64);
                    klog::write_raw(b"\n");

                    // F33: map the BAR holding the MSI-X table and read
                    // each entry's vector_control. At reset the spec says
                    // every entry is masked (bit 0 of vector_control set).
                    let bars2 = {
                        #[cfg(target_arch = "x86_64")]
                        { let r = hal_x86_64::pci::LegacyPci;
                          pci::decode_bars(&r, bdf) }
                        #[cfg(target_arch = "aarch64")]
                        { match hal_aarch64::pci::EcamPci::from_published() {
                            Some(r) => pci::decode_bars(&r, bdf),
                            None => [pci::Bar::None; 6],
                        } }
                    };
                    let tbar_pa = match bars2[m.table_bir as usize] {
                        pci::Bar::Mem32 { base, .. } => base as u64,
                        pci::Bar::Mem64 { base, .. } => base,
                        _ => 0,
                    };
                    if tbar_pa != 0 {
                        let tbl_pa = tbar_pa + m.table_offset as u64;
                        let page_pa = tbl_pa & !0xFFF;
                        let page_off = tbl_pa - page_pa;
                        // SAFETY: BAR PA decoded from cap; bump VA private.
                        let base_va = unsafe { map_mmio_pages(page_pa, 1) };
                        let tbl_va = base_va + page_off;
                        // Read up to 4 entries (cap of MAX MSI-X size for
                        // virtio-net here) and log vector_control.
                        let n = if m.table_size > 4 { 4 } else { m.table_size };
                        for i in 0..n {
                            let entry_va = tbl_va + (i as u64) * 16;
                            // SAFETY: entry_va is Device-attr; aligned u32 reads.
                            let vc = unsafe {
                                core::ptr::read_volatile((entry_va + 12) as *const u32)
                            };
                            klog::write_raw(b"[INFO]  msix-tbl ");
                            klog::write_dec_u64(bdf.bus as u64);
                            klog::write_raw(b":");
                            klog::write_dec_u64(bdf.device as u64);
                            klog::write_raw(b".");
                            klog::write_dec_u64(bdf.function as u64);
                            klog::write_raw(b" v=");
                            klog::write_dec_u64(i as u64);
                            klog::write_raw(b" ctl=");
                            klog::write_hex_u64(vc as u64);
                            klog::write_raw(b" masked=");
                            klog::write_dec_u64((vc & 0x1) as u64);
                            klog::write_raw(b"\n");
                        }
                    }
                }
            }
        }
        if virtio::is_modern(d.vendor_id, d.device_id) {
            let vcaps = {
                #[cfg(target_arch = "x86_64")]
                {
                    let r = hal_x86_64::pci::LegacyPci;
                    virtio::decode_all(&r, bdf, &caps)
                }
                #[cfg(target_arch = "aarch64")]
                {
                    match hal_aarch64::pci::EcamPci::from_published() {
                        Some(r) => virtio::decode_all(&r, bdf, &caps),
                        None    => virtio::pci::heapless_v::VCapVec::new(),
                    }
                }
            };
            for v in vcaps.iter() {
                klog::write_raw(b"[INFO]  virtio-cap ");
                klog::write_dec_u64(bdf.bus as u64);
                klog::write_raw(b":");
                klog::write_dec_u64(bdf.device as u64);
                klog::write_raw(b".");
                klog::write_dec_u64(bdf.function as u64);
                klog::write_raw(b" type=");
                klog::write_dec_u64(v.cfg_type as u64);
                klog::write_raw(b" bar=");
                klog::write_dec_u64(v.bar as u64);
                klog::write_raw(b" off=");
                klog::write_hex_u64(v.offset as u64);
                klog::write_raw(b" len=");
                klog::write_hex_u64(v.length as u64);
                if v.cfg_type == virtio::VIRTIO_PCI_CAP_NOTIFY_CFG {
                    klog::write_raw(b" notify_mult=");
                    klog::write_hex_u64(v.notify_off_multiplier as u64);
                }
                klog::write_raw(b"\n");
            }
        }
    }
}

/// Enumerate the live PCI bus and emit a `[INFO] pci ...` line per
/// device under `debug-boot`. v1 only walks bus 0 (single segment);
/// multi-bus discovery rides alongside the real driver work.
/// # SAFETY: caller is the boot path; per-arch ConfigSpaceReader
/// has been brought up (CF8/CFC available on x86; ECAM device-mapped
/// + `ECAM_BASE_VA` published on aarch64).
/// # C: O(N_bdfs probed)
pub fn enumerate_and_log() {
    debug_boot! {
        let devs = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
                pci::enumerate(&r)
            }
            #[cfg(target_arch = "aarch64")]
            {
                match hal_aarch64::pci::EcamPci::from_published() {
                    // ECAM mapping is bus 0 only on aarch64 v1 (1 MiB
                    // device-mapped at boot); enumerate cap matches.
                    Some(r) => pci::enumerate_buses(&r, 1),
                    None    => alloc::vec::Vec::new(),
                }
            }
        };
        klog::write_raw(b"[INFO]  pci: devices=");
        klog::write_dec_u64(devs.len() as u64);
        klog::write_raw(b"\n");
        for d in devs.iter().take(16) {
            klog::write_raw(b"[INFO]  pci ");
            klog::write_dec_u64(d.bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(d.bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(d.bdf.function as u64);
            klog::write_raw(b" vendor=");
            klog::write_hex_u64(d.vendor_id as u64);
            klog::write_raw(b" device=");
            klog::write_hex_u64(d.device_id as u64);
            klog::write_raw(b" class=");
            klog::write_hex_u64(d.class_code as u64);
            klog::write_raw(b"\n");
            // Capability list — modern devices always advertise MSI-X
            // + (for virtio) vendor-specific virtio-pci caps. Foundation
            // for upcoming MSI-X routing + virtio modern-transport work.
            bar_dump_arch(d.bdf);
            cap_dump_arch(d);
            virtio_probe_arch(d);
        }
    }
}
