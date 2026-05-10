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

/// Enable PCI command reg bits 1 (Memory Space) + 2 (Bus Master) on
/// `bdf`. UEFI on QEMU virt leaves Memory OFF; without this any BAR
/// MMIO read returns 0xFFFFFFFF and any write is silently dropped.
/// # C: O(1) — one config-space R/W pair.
fn enable_pci_mem_bm(bdf: pci::Bdf) {
    use pci::ConfigSpaceReader as _;
    let cur = {
        #[cfg(target_arch = "x86_64")]
        { let r = hal_x86_64::pci::LegacyPci;
          <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04) }
        #[cfg(target_arch = "aarch64")]
        { match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, 0x04),
            None => return,
        } }
    };
    let new = (cur & 0xFFFF_0000) | ((cur & 0xFFFF) | 0x0006);
    if new == cur { return; }
    #[cfg(target_arch = "x86_64")]
    { let r = hal_x86_64::pci::LegacyPci;
      <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, new); }
    #[cfg(target_arch = "aarch64")]
    { if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
        <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&r, bdf, 0x04, new);
    } }
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
                        // F38: program entry 0 with a real GICv2m MSI
                        // message on aarch64. Allocate one SPI, enable
                        // it at the GIC distributor, write the table
                        // entry, leave masked (vector_control bit 0=1)
                        // so no IRQ fires until F39 binds queue_msix
                        // and the dispatcher learns to route the SPI.
                        // F56-08: prefer the ITS path on virtio-blk
                        // (DeviceID 0x10 was pre-bound to LPI 8192 in
                        // smoke_device_map_arm), fall back to GICv2m
                        // SPI for everyone else. If neither is
                        // available, skip the bind and let the
                        // device sit in INTx-style ISR delivery.
                        // F57: per-arch MSI bind. aarch64 prefers ITS
                        // for virtio-blk (DeviceID 0x10 → LPI 8192,
                        // bound by smoke_device_map_arm), falls back
                        // to GICv2m SPI. x86 allocates an IDT vector
                        // (`VEC_MSI = 0x50`) and writes the LAPIC MSI
                        // message addr `0xFEE0_0000` (boot CPU dest=0,
                        // RH=0, DM=0, Fixed delivery).
                        let bind: Option<(u32, u64, u32)> = {
                            #[cfg(target_arch = "aarch64")]
                            {
                                let its_translater = arch_irq::its::translater_pa();
                                let is_blk_bdf = bdf.bus == 0 && bdf.device == 2 && bdf.function == 0;
                                let use_its = its_translater != 0 && is_blk_bdf;
                                if use_its {
                                    Some((0u32, its_translater, 0u32))
                                } else if let Some(spi) = arch_irq::alloc_arm_spi() {
                                    // SAFETY: SPI freshly allocated, range owned by msi.rs; gic was enabled by smoke_device_map_arm; single-CPU pre-init context for boot probe.
                                    unsafe { arch_irq::gic::enable_intid(spi); }
                                    let v2m_pa = crate::acpi::GIC_MSI_FRAME_PA
                                        .load(core::sync::atomic::Ordering::Acquire);
                                    Some((spi, v2m_pa + 0x40, spi))
                                } else {
                                    None
                                }
                            }
                            #[cfg(target_arch = "x86_64")]
                            {
                                if let Some(vec) = arch_irq::alloc_x86_vector() {
                                    Some((vec as u32, 0xFEE0_0000u64, vec as u32))
                                } else { None }
                            }
                        };
                        if let Some((id, msg_addr, msg_data)) = bind {
                            let entry_va = tbl_va; // entry 0
                            // SAFETY: entry_va is the freshly Device-attr-mapped MSI-X table base; aligned u32 stores within the 16-byte entry.
                            unsafe {
                                core::ptr::write_volatile(entry_va as *mut u32,
                                    (msg_addr & 0xFFFF_FFFF) as u32);
                                core::ptr::write_volatile((entry_va + 4) as *mut u32,
                                    (msg_addr >> 32) as u32);
                                core::ptr::write_volatile((entry_va + 8) as *mut u32,
                                    msg_data);
                                // F39: unmask the vector (vector_control bit 0 = 0).
                                // The handler in oxide_arm_irq_dispatch only
                                // bumps a counter today, so spurious fires are
                                // harmless; F40 will bind to a real callback.
                                core::ptr::write_volatile((entry_va + 12) as *mut u32, 0);
                            }
                            // F39: set MSI-X Enable bit (bit 15 of message
                            // control at cap_off+0x02). PCI 3.0 §6.8.2 —
                            // until this is set the device routes IRQs via
                            // INTx and ignores table entries.
                            #[cfg(target_arch = "aarch64")]
                            { if let Some(rr) = hal_aarch64::pci::EcamPci::from_published() {
                                use pci::ConfigSpaceReader as _;
                                let off = c.cfg_off & 0xFC;
                                let cur = <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&rr, bdf, off);
                                let new = cur | (1u32 << 31); // MC bit 15 -> dword bit 31
                                <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&rr, bdf, off, new);
                            } }
                            #[cfg(target_arch = "x86_64")]
                            { let rr = hal_x86_64::pci::LegacyPci;
                              use pci::ConfigSpaceReader as _;
                              let off = c.cfg_off & 0xFC;
                              let cur = <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::read32(&rr, bdf, off);
                              let new = cur | (1u32 << 31);
                              <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::write32(&rr, bdf, off, new);
                            }
                            // F41: re-read message_control to verify the
                            // Enable bit stuck. If `mc_after & 0x8000 == 0`
                            // then the device rejected the write (bit is
                            // RO), and the device will keep delivering via
                            // INTx (ISR bit) instead of MSI-X.
                            let mc_after = {
                                #[cfg(target_arch = "aarch64")]
                                { match hal_aarch64::pci::EcamPci::from_published() {
                                    Some(rr) => {
                                        use pci::ConfigSpaceReader as _;
                                        <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&rr, bdf, c.cfg_off & 0xFC) >> 16
                                    }
                                    None => 0,
                                } }
                                #[cfg(target_arch = "x86_64")]
                                { let rr = hal_x86_64::pci::LegacyPci;
                                  use pci::ConfigSpaceReader as _;
                                  <hal_x86_64::pci::LegacyPci as pci::ConfigSpaceReader>::read32(&rr, bdf, c.cfg_off & 0xFC) >> 16 }
                            };
                            klog::write_raw(b"[INFO]  msix-en ");
                            klog::write_dec_u64(bdf.bus as u64);
                            klog::write_raw(b":");
                            klog::write_dec_u64(bdf.device as u64);
                            klog::write_raw(b".");
                            klog::write_dec_u64(bdf.function as u64);
                            klog::write_raw(b" mc=");
                            klog::write_hex_u64(mc_after as u64);
                            klog::write_raw(b" enabled=");
                            klog::write_dec_u64(((mc_after >> 15) & 1) as u64);
                            klog::write_raw(b"\n");
                            // Read back to confirm the writes landed.
                            // SAFETY: same Device-attr-mapped entry; aligned u32 loads of fields just written.
                            let (al, ah, dt, vc) = unsafe {(
                                core::ptr::read_volatile(entry_va as *const u32),
                                core::ptr::read_volatile((entry_va + 4) as *const u32),
                                core::ptr::read_volatile((entry_va + 8) as *const u32),
                                core::ptr::read_volatile((entry_va + 12) as *const u32),
                            )};
                            klog::write_raw(b"[INFO]  msix-bind ");
                            klog::write_dec_u64(bdf.bus as u64);
                            klog::write_raw(b":");
                            klog::write_dec_u64(bdf.device as u64);
                            klog::write_raw(b".");
                            klog::write_dec_u64(bdf.function as u64);
                            klog::write_raw(b" spi=");
                            klog::write_dec_u64(id as u64);
                            klog::write_raw(b" addr=");
                            klog::write_hex_u64(((ah as u64) << 32) | (al as u64));
                            klog::write_raw(b" data=");
                            klog::write_hex_u64(dt as u64);
                            klog::write_raw(b" ctl=");
                            klog::write_hex_u64(vc as u64);
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
            // F38 ordering fix: enable Memory + BusMaster bits in the
            // PCI command reg BEFORE cap_dump_arch tries to read or
            // write the MSI-X table BAR. Previously this only happened
            // inside virtio_probe_arch (which runs LAST), so MSI-X
            // table writes from cap_dump bounced as 0xFF reads.
            enable_pci_mem_bm(d.bdf);
            // Capability list — modern devices always advertise MSI-X
            // + (for virtio) vendor-specific virtio-pci caps. Foundation
            // for upcoming MSI-X routing + virtio modern-transport work.
            bar_dump_arch(d.bdf);
            cap_dump_arch(d);
            virtio_probe_arch(d);
        }
        // F40 + F57: brief IRQ unmask window so any MSIs queued
        // during the closed-loop drain through the per-arch IRQ
        // dispatcher and bump MSI_FIRES. Without this the counter
        // stays 0 (canary.rs leaves IRQs masked on the boot CPU
        // before pci_boot runs on both arches).
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: boot phase, GIC enabled by smoke_device_map_arm; brief unmask window mirrors arm-timer smoke; we re-mask immediately after the spin.
            unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)); }
            for _ in 0..2_000_000 { core::hint::spin_loop(); }
            // SAFETY: pairs with daifclr above, restoring boot-mask state.
            unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: boot phase; LAPIC enabled by device_map_smoke; brief STI window drains queued MSI IRRs into the IDT vec=0x50 stub which bumps MSI_FIRES.
            unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
            for _ in 0..2_000_000 { core::hint::spin_loop(); }
            // F57 self-fire: write LAPIC ICR-LO with self-shorthand
            // (bits 19:18 = 01) + vec 0x50 + Fixed delivery + level
            // assert. If MSI_FIRES bumps post this write, the IDT
            // entry for 0x50 + dispatcher arm + LAPIC EOI path are
            // all correct end-to-end and any device-driven MSI gap
            // is in the PCI MSI write path, not kernel.
            let pre = arch_irq::MSI_FIRES.load(core::sync::atomic::Ordering::Acquire);
            // SAFETY: LAPIC mapped+enabled; ICR write is well-defined; self-shorthand targets this CPU; IF=1 from the sti above.
            unsafe {
                let va = arch_irq::lapic::LAPIC_BASE_VA.load(core::sync::atomic::Ordering::Acquire);
                if va != 0 {
                    let icr_lo = (1u32 << 18) | (1u32 << 14) | 0x50;
                    core::ptr::write_volatile((va + 0x300) as *mut u32, icr_lo);
                }
            }
            for _ in 0..1_000_000 { core::hint::spin_loop(); }
            let post = arch_irq::MSI_FIRES.load(core::sync::atomic::Ordering::Acquire);
            klog::write_raw(b"[INFO]  lapic-self-fire pre=");
            klog::write_dec_u64(pre as u64);
            klog::write_raw(b" post=");
            klog::write_dec_u64(post as u64);
            klog::write_raw(b" delta=");
            klog::write_dec_u64((post - pre) as u64);
            klog::write_raw(b"\n");
            // SAFETY: pairs with sti above; restores canary's boot-mask state.
            unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
        }
        let fires = arch_irq::MSI_FIRES
            .load(core::sync::atomic::Ordering::Acquire);
        klog::write_raw(b"[INFO]  msi-fires-post-enum=");
        klog::write_dec_u64(fires as u64);
        klog::write_raw(b"\n");

        // F59-15: register the modern virtio-net device as a NetDev
        // and install a default L2 route. ARP/ICMP-request/DHCP
        // belong in user-space (`dhclient`, `ping`, etc.) — the
        // kernel only provides the iface + protocol stack via the
        // AF_INET socket API. Userspace gets the iface up via
        // ioctl/netlink (TODO) and runs DHCP from there.
        if crate::dev::virtio_net_modern::is_modern_present() {
            if let Some(dev) = crate::dev::virtio_net_modern::VirtioNetDev::new() {
                let stack = net::sock::stack();
                let id = stack.ifaces.register(
                    dev as alloc::sync::Arc<dyn net::NetDev>,
                );
                klog::write_raw(b"[INFO]  virtio-net-iface registered id=");
                klog::write_dec_u64(id.0 as u64);
                klog::write_raw(b" name=eth0\n");
            }
        }

        // F46: read GICD_ISPENDR2 (covers SPIs 64..95). If SPI 81 or
        // 82 is pending here, the device-driven MSI write reached
        // the GIC but didn't deliver to CPU (mask/priority issue).
        // If both bits are clear, the MSI write never reached the
        // distributor at all (PCI root-complex routing dropped it).
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: GIC was mapped+enabled by smoke_device_map_arm; diagnostic read of ISPENDR via the published GICD_VA.
            let ispendr2 = unsafe { arch_irq::gic::ispendr_word(81) };
            klog::write_raw(b"[INFO]  gicd-ispendr2=");
            klog::write_hex_u64(ispendr2 as u64);
            klog::write_raw(b" spi81_bit=");
            klog::write_dec_u64(((ispendr2 >> (81 - 64)) & 1) as u64);
            klog::write_raw(b" spi82_bit=");
            klog::write_dec_u64(((ispendr2 >> (82 - 64)) & 1) as u64);
            klog::write_raw(b"\n");
        }

        // F45: GICv2m self-fire diagnostic. Allocate a fresh SPI,
        // enable it at the GICD, then write the SPI number to the
        // v2m frame's SETSPI_NS register (+0x040) FROM THE KERNEL.
        // If MSI_FIRES bumps, the v2m frame + GIC delivery path
        // works end-to-end and the silent-MSI is device-side
        // (QEMU virtio-pci ignored the msg_addr we wrote). If it
        // does not bump, the v2m frame is inert under this QEMU
        // virt configuration and silent-MSI requires a different
        // delivery path (e.g. GICv3 + ITS).
        #[cfg(target_arch = "aarch64")]
        {
            let v2m_va = arch_irq::GICV2M_VA
                .load(core::sync::atomic::Ordering::Acquire);
            if v2m_va != 0 {
                if let Some(spi) = arch_irq::alloc_arm_spi() {
                    // SAFETY: gic::enable was called before any IRQ unmask; SPI is freshly allocated, owned by this diagnostic; single-CPU pre-init.
                    unsafe { arch_irq::gic::enable_intid(spi); }
                    let before = arch_irq::MSI_FIRES
                        .load(core::sync::atomic::Ordering::Acquire);
                    let setspi_ns = (v2m_va + 0x040) as *mut u32;
                    // SAFETY: boot phase, single-CPU; brief unmask
                    // window mirrors F40 above; v2m_va is freshly
                    // Device-attr mapped, +0x40 is the SETSPI_NS
                    // doorbell within the same 4 KiB; SPI is enabled.
                    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)); }
                    // SAFETY: aligned u32 write to SETSPI_NS register, value is the target SPI number.
                    unsafe { core::ptr::write_volatile(setspi_ns, spi); }
                    for _ in 0..2_000_000 { core::hint::spin_loop(); }
                    // SAFETY: pairs with the daifclr above; restores the boot-mask state on this CPU.
                    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
                    let after = arch_irq::MSI_FIRES
                        .load(core::sync::atomic::Ordering::Acquire);
                    klog::write_raw(b"[INFO]  gicv2m-self-fire spi=");
                    klog::write_dec_u64(spi as u64);
                    klog::write_raw(b" before=");
                    klog::write_dec_u64(before as u64);
                    klog::write_raw(b" after=");
                    klog::write_dec_u64(after as u64);
                    klog::write_raw(b" delta=");
                    klog::write_dec_u64((after - before) as u64);
                    klog::write_raw(b"\n");
                }
            }
            // F48: open a longer unmask window so any bytes pushed
            // into the UART RX FIFO via qemu_send_serial (or typing)
            // during boot get a chance to fire SPI 33. Logs the
            // UART IRQ counter delta — nonzero proves the
            // IRQ-driven RX path replaces the timer-poll fallback.
            let uart_before = arch_irq::gic::UART_IRQ_FIRES
                .load(core::sync::atomic::Ordering::Acquire);
            // SAFETY: brief unmask window, mirrors F40 pattern; gic+pl011 already up.
            unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)); }
            for _ in 0..200_000_000 { core::hint::spin_loop(); }
            // SAFETY: pairs with the daifclr above; restores boot-mask state on this CPU.
            unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
            let uart_after = arch_irq::gic::UART_IRQ_FIRES
                .load(core::sync::atomic::Ordering::Acquire);
            klog::write_raw(b"[INFO]  uart-irq-fires before=");
            klog::write_dec_u64(uart_before as u64);
            klog::write_raw(b" after=");
            klog::write_dec_u64(uart_after as u64);
            klog::write_raw(b" delta=");
            klog::write_dec_u64((uart_after - uart_before) as u64);
            klog::write_raw(b"\n");
        }
    }
}
