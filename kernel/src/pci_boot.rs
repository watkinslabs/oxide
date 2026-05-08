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
/// negotiation, queue size scan) runs unconditionally; only the
/// trace logging consumes this struct under `debug_boot!`.
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
