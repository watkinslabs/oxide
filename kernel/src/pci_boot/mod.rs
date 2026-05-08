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
pub(super) unsafe fn map_mmio_pages(pa: u64, n_pages: u64) -> u64 {
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

// Submodule named `virtio_drv` (not `virtio`) so it doesn't shadow
// the external `virtio` crate dependency referenced elsewhere in this
// file (cap_dump_arch reads `virtio::is_modern`, etc.).
mod virtio_drv;
use virtio_drv::virtio_probe_arch;

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
