#![no_std]
#![cfg(target_os = "oxide-kernel")]
#[macro_use] extern crate kmacros;
extern crate alloc;

// PCI enumeration boot helper — wraps `pci::enumerate` with per-arch
// `ConfigSpaceReader` selection (x86 LegacyPci CF8/CFC, aarch64
// EcamPci MMIO seeded by `device_map_smoke_arm`). Split out of
// `lib.rs` to keep that file under the 1000-line cap (08§7).

/// Map `n_pages` of MMIO at PA `pa` (4K-aligned) into kernel VA space.
/// Returns the base VA.
/// # SAFETY: caller asserts (a) `pa` names a real device region the
/// kernel exclusively owns, (b) PMM ready + single-CPU + IRQs masked,
/// (c) `pa` is 4K-aligned. Used only at boot for virtio probing.
/// # C: O(n_pages × walk depth)
pub(crate) unsafe fn map_mmio_pages(pa: u64, n_pages: u64) -> u64 {
    unsafe { mmio_map::map_pages(pa, n_pages) }
}

// Submodule named `virtio_drv` (not `virtio`) so it doesn't shadow
// the external `virtio` crate dependency referenced elsewhere in this
// file (cap_dump_arch reads `virtio::is_modern`, etc.).
mod virtio_drv;
mod virtio_child;
mod virtio_trace;
mod virtio_transport;

/// Monotonic virtio-bus sequence (`virtioN` naming) assigned in
/// enumeration order, mirroring Linux's virtio-pci registration.
static VIRTIO_SEQ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Next virtio bus index. # C: O(1)
fn virtio_seq() -> u32 { VIRTIO_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed) }

/// Register PCI model drivers known at boot. Matching and probe are still
/// driven by `drv::auto_bind` on each enumerated PCI device.
/// # C: O(N_drivers)
fn register_pci_model_drivers() {
    drv::register_driver(&drv_nvme::NVME_DRIVER);
    drv::register_driver(&drv_ahci::AHCI_DRIVER);
    virtio_drv::register_model_drivers();
}

/// Emit one `[INFO] pci-bar <bdf> N <kind>=...` line per programmed BAR.
/// # C: O(1) — at most 6 BARs.
fn bar_dump_arch(bdf: pci::Bdf) {
    #[cfg(not(feature = "debug-boot"))]
    let _ = bdf;
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

fn pci_resources_arch(bdf: pci::Bdf) -> alloc::vec::Vec<drv::Resource> {
    let resources = {
        #[cfg(target_arch = "x86_64")]
        {
            let r = hal_x86_64::pci::LegacyPci;
            pci::probe_bar_resources(&r, bdf)
        }
        #[cfg(target_arch = "aarch64")]
        {
            match hal_aarch64::pci::EcamPci::from_published() {
                Some(r) => pci::probe_bar_resources(&r, bdf),
                None => [None; 6],
            }
        }
    };
    resources
        .iter()
        .filter_map(|r| r.map(|r| drv::Resource { start: r.start, end: r.end, flags: r.flags }))
        .collect()
}

/// Per-arch wrapper that walks the capability list for one BDF and
/// emits `[INFO] pci-cap ... id=...` lines. For modern virtio devices
/// (vendor=0x1AF4, device=0x1041..=0x107f) it also decodes each vendor cap and
/// emits a `[INFO] virtio-cap ...` line per cfg_type.
/// # C: O(N_caps) — typical N is 1–6.
fn cap_dump_arch(d: &pci::PciDevice) {
    let bdf = d.bdf;
    #[cfg(not(feature = "debug-boot"))]
    let _ = bdf;
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
                        // Capability dumping is read-only. MSI-X programming
                        // belongs to the bound PCI transport driver, which can
                        // pair allocation with remove-time teardown.
                        unsafe { mmio_map::unmap_pages(base_va, 1); }
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
    debug_boot! {
        klog::write_raw(b"[INFO]  pci: devices=");
        klog::write_dec_u64(devs.len() as u64);
        klog::write_raw(b"\n");
    }
    register_pci_model_drivers();
    for d in devs.iter() {
        debug_boot! {
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
        }
        bar_dump_arch(d.bdf);
        cap_dump_arch(d);

        let class24 = ((d.class_code as u32) << 16)
            | ((d.subclass as u32) << 8) | (d.prog_if as u32);
        let addr = alloc::format!("{:04x}:{:02x}:{:02x}.{}",
            0u16, d.bdf.bus, d.bdf.device, d.bdf.function);
        let pci_dev = drv::device_add(alloc::sync::Arc::new(
            drv::Device::new("pci", addr, d.vendor_id, d.device_id, class24)
                .with_resources(pci_resources_arch(d.bdf))));
        let _ = drv::auto_bind(&pci_dev);
    }

    // F40 + F57: brief IRQ unmask window so any MSIs queued during
    // the closed-loop drain through the per-arch IRQ dispatcher.
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: boot phase, GIC enabled by smoke_device_map_arm; brief
        // unmask window mirrors arm-timer smoke; restore boot-mask state.
        unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)); }
        for _ in 0..2_000_000 { core::hint::spin_loop(); }
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: boot phase; LAPIC enabled by device_map_smoke; brief STI
        // window drains queued MSI IRRs into the IDT vec=0x50 stub.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
        for _ in 0..2_000_000 { core::hint::spin_loop(); }
        debug_boot! {
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
        }
        // SAFETY: pairs with sti above; restores canary's boot-mask state.
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
    }
    debug_boot! {
        let fires = arch_irq::MSI_FIRES
            .load(core::sync::atomic::Ordering::Acquire);
        klog::write_raw(b"[INFO]  msi-fires-post-enum=");
        klog::write_dec_u64(fires as u64);
        klog::write_raw(b"\n");
    }

    // F59-15: install the default L2/netlink route state for the netdev
    // already registered by virtio-net's model probe.
    if let Some(id) = drv_virtio_net::modern::registered_iface() {
            let stack = net::sock::stack();

            let lo_idx = stack.ifaces.lookup_name("lo").map(|(id, _)| id.0);
            ::netlink::rtnetlink::seed_defaults(Some(id.0), lo_idx);
            ::netlink::rtnetlink::seed_default_routes(id.0);
            if let Some(lo_idx) = lo_idx {
                ::netlink::rtnetlink::seed_default_routes_lo(lo_idx);
            }
            let _ = stack.send_router_solicitation(id, net::Ipv6Addr::ANY);
    }

    debug_boot! {
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
                    let _ = arch_irq::free_arm_spi(spi);
                }
            }
            // F48: open a longer unmask window so any bytes pushed
            // into the UART RX FIFO via qemu_send_serial (or typing)
            // during boot get a chance to fire SPI 33. Logs the
            // UART IRQ counter delta; nonzero proves the RX path is IRQ-driven.
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
