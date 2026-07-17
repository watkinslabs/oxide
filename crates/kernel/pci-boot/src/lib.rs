#![no_std]
#![cfg(target_os = "oxide-kernel")]
#[macro_use] extern crate kmacros;
extern crate alloc;

// PCI enumeration boot helper — wraps `pci::enumerate` with per-arch
// ECAM `ConfigSpaceReader` selection seeded by device-map bring-up. Split out of
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
mod virtio_bus;
mod virtio_child;
mod virtio_drv;
mod trace;
mod virtio_trace;
mod virtio_transport;

/// Monotonic virtio-bus sequence (`virtioN` naming) assigned in
/// enumeration order, mirroring Linux's virtio-pci registration.
static VIRTIO_SEQ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Next virtio bus index. # C: O(1)
fn virtio_seq() -> u32 { VIRTIO_SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed) }

/// Register PCI model drivers known at boot. Matching and probe are driven by
/// driver-core attachment from `register_driver` and `device_add`.
/// # C: O(N_drivers)
fn register_pci_model_drivers() {
    drv::register_driver(&drv_nvme::NVME_DRIVER);
    drv::register_driver(&drv_ahci::AHCI_DRIVER);
    virtio_drv::register_model_drivers();
}

fn pci_resources_arch(bdf: pci::Bdf) -> alloc::vec::Vec<drv::Resource> {
    let resources = {
        #[cfg(target_arch = "x86_64")]
        {
            match hal_x86_64::pci::EcamPci::from_published() {
                Some(r) => pci::probe_bar_resources(&r, bdf),
                None => [None; 6],
            }
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
        .enumerate()
        .filter_map(|(bar, r)| r.map(|r| drv::Resource {
            bar: bar as u8,
            start: r.start,
            end: r.end,
            flags: r.flags,
        }))
        .collect()
}

/// Enumerate the live PCI bus and emit a `[INFO] pci ...` line per
/// device under `debug-boot`. The PCI crate walks bridge windows; arch
/// setup still determines which config-space buses are addressable.
/// # SAFETY: caller is the boot path; per-arch ConfigSpaceReader
/// has been brought up and `ECAM_BASE_VA` published.
/// # C: O(N_bdfs probed)
pub fn enumerate_and_log() {
    let devs = {
        #[cfg(target_arch = "x86_64")]
        {
            match hal_x86_64::pci::EcamPci::from_published() {
                Some(r) => pci::enumerate_buses(&r, firmware::acpi::ecam_bus_cap()),
                None => alloc::vec::Vec::new(),
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            match hal_aarch64::pci::EcamPci::from_published() {
                Some(r) => pci::enumerate_buses(&r, firmware::acpi::ecam_bus_cap()),
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
        trace::bar_dump_arch(d.bdf);
        trace::cap_dump_arch(d);

        let class24 = ((d.class_code as u32) << 16)
            | ((d.subclass as u32) << 8) | (d.prog_if as u32);
        let addr = alloc::format!("{:04x}:{:02x}:{:02x}.{}",
            0u16, d.bdf.bus, d.bdf.device, d.bdf.function);
        if publish_pci_model_device(d, addr, class24).is_none() {
            continue;
        }
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

    // F59-15: install the default L2/netlink route state for every netdev
    // already registered by virtio-net's model probe.
    {
        let stack = net::sock::stack();
        let lo_idx = stack.ifaces.lookup_name("lo").map(|(id, _)| id.0);
        ::netlink::rtnetlink::seed_defaults(None, lo_idx);
        if let Some(lo_idx) = lo_idx {
            ::netlink::rtnetlink::seed_default_routes_lo(lo_idx);
        }
        for (_device_key, id) in drv_virtio_net::modern::registered_ifaces() {
            // The QEMU user network contract is the boot-time v1 network
            // identity. Publish it through NetStack so the address table and
            // virtio-net RX runtime receive the same primary address.
            let oxide_guest_ip = net::Ipv4Addr::new(10, 0, 2, 15);
            let oxide_guest_mask = net::Ipv4Addr::new(255, 255, 255, 0).as_u32();
            let _ = stack.set_primary_ipv4_in(
                0, id, oxide_guest_ip, ::netlink::rtnetlink::RT_SCOPE_UNIVERSE,
            );
            let _ = stack.set_primary_ipv4_mask_in(0, id, oxide_guest_mask);
            ::netlink::rtnetlink::seed_default_routes(id.0);
            let _ = stack.send_router_solicitation(id, net::Ipv6Addr::ANY);
        }
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

fn publish_pci_model_device(
    d: &pci::PciDevice,
    addr: alloc::string::String,
    class24: u32,
) -> Option<alloc::sync::Arc<drv::Device>> {
    let dev = alloc::sync::Arc::new(
        drv::Device::new("pci", addr.clone(), d.vendor_id, d.device_id, class24)
            .with_resources(pci_resources_arch(d.bdf)),
    );
    match drv::try_device_add(dev) {
        Ok(dev) => Some(dev),
        Err(drv::Error::Busy) => drv::devices().into_iter().find(|dev| {
            dev.bus == "pci"
                && dev.addr.as_str() == addr.as_str()
                && dev.vendor_id == d.vendor_id
                && dev.device_id == d.device_id
                && dev.class == class24
        }),
        Err(_) => None,
    }
}
