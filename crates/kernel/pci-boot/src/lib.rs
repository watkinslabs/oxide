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
/// Sole caller is `trace.rs`'s MSI-X table dump, itself `debug-boot`-only.
#[cfg(feature = "debug-boot")]
pub(crate) unsafe fn map_mmio_pages(pa: u64, n_pages: u64) -> u64 {
    // SAFETY: this fn is itself `unsafe` and forwards its contract unchanged —
    // `pa` names a 4K-aligned device region the kernel exclusively owns, at
    // boot with the PMM ready, single-CPU, IRQs masked.
    unsafe { mmio_map::map_pages(pa, n_pages) }
}

// Submodule named `virtio_drv` (not `virtio`) so it doesn't shadow
// the external `virtio` crate dependency referenced elsewhere in this
// file (cap_dump_arch reads `virtio::is_modern`, etc.).
mod config_access;
mod virtio_bus;
mod virtio_child;
mod virtio_drv;
mod trace;
#[cfg(feature = "debug-boot")]
mod virtio_trace;
mod virtio_transport;
mod amd_vi_events;
#[cfg(target_arch = "x86_64")]
mod vtd_faults;

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
    drv::register_driver(&drv_e1000::E1000_DRIVER);
    drv::register_driver(&drv_e1000::E1000E_DRIVER);
    drv::register_driver(&drv_igc::IGC_DRIVER);
    drv::register_driver(&drv_rtl8125::RTL8125_DRIVER);
    drv::register_driver(&drv_atlantic::ATLANTIC_DRIVER);
    #[cfg(target_arch = "x86_64")]
    drv::register_driver(&drv_bochs::BOCHS_DRIVER);
    drv::register_driver(&drv_xhci::XHCI_DRIVER);
    virtio_drv::register_model_drivers();
}

fn resolve_firmware_intx(bdf: pci::Bdf, pin: u8) -> Option<pci_irq::IntxRoute> {
    let route = firmware::acpi::pci_intx_route(bdf, pin)?;
    Some(pci_irq::IntxRoute { gsi: route.gsi, level: route.level, active_low: route.active_low })
}

/// Map every firmware-published I/O APIC before IRQ-enabled PCI probing.
/// # C: O(N_IOAPIC)
#[cfg(target_arch = "x86_64")]
fn map_firmware_ioapics() -> bool {
    for index in 0..firmware::ioapic_count() {
        let Some(ioapic) = firmware::ioapic(index) else { return false; };
        // SAFETY: MADT supplied a page-aligned controller MMIO PA; PCI boot owns permanent mappings before STI.
        let va = unsafe { mmio_map::map_pages(ioapic.pa, 1) };
        if !hal_x86_64::ioapic::set_gsi_base_va(ioapic.id, ioapic.gsi_base, va) { return false; }
    }
    true
}

#[cfg(target_arch = "aarch64")]
fn map_firmware_ioapics() -> bool { true }

/// Activate VT-d through the architecture's live ECAM reader before driver probing.
/// # C: O(units + requesters + RAM leaves)
fn activate_vtd_arch(_requesters: &[pci::Bdf], _aliases: &pci::DmaAliases) -> iommu::VtdActivation {
    #[cfg(target_arch = "x86_64")]
    {
        let Some(reader) = hal_x86_64::pci::EcamPci::from_published() else { return iommu::VtdActivation::Bypass; };
        // SAFETY: PCI enumeration has not registered a driver or admitted bus mastering yet.
        return unsafe { iommu::activate_vtd(&reader, _requesters, _aliases, pmm::user_as::hhdm_offset(), pmm::setup::usable_regions()) };
    }
    #[cfg(target_arch = "aarch64")]
    { iommu::VtdActivation::Bypass }
}

/// Stop firmware-owned DMA before IOMMU tables are published.
///
/// Memory decoding remains available for later BAR discovery; only the bus
/// master command bit is removed. Driver probe restores it after admission.
/// # C: O(requesters)
fn quiesce_bus_masters(requesters: &[pci::Bdf]) {
    #[cfg(target_arch = "x86_64")]
    if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() {
        for &bdf in requesters { let _ = pci::clear_bus_master(&reader, bdf); }
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(reader) = hal_aarch64::pci::EcamPci::from_published() {
        for &bdf in requesters { let _ = pci::clear_bus_master(&reader, bdf); }
    }
}

fn pci_resources_arch(d: &pci::PciDevice) -> alloc::vec::Vec<drv::Resource> {
    let bars = {
        #[cfg(target_arch = "x86_64")]
        {
            match hal_x86_64::pci::EcamPci::from_published() {
                Some(r) => pci::probe_bar_resources(&r, d.bdf),
                None => [None; 6],
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            match hal_aarch64::pci::EcamPci::from_published() {
                Some(r) => pci::probe_bar_resources(&r, d.bdf),
                None => [None; 6],
            }
        }
    };
    let mut resources: alloc::vec::Vec<_> = bars
        .iter()
        .enumerate()
        .filter_map(|(bar, r)| r.map(|r| drv::Resource {
            bar: bar as u8,
            start: r.start,
            end: r.end,
            flags: r.flags,
        }))
        .collect();
    if d.header_type & pci::uapi::HEADER_TYPE_MASK == pci::uapi::HEADER_TYPE_BRIDGE {
        let windows = {
            #[cfg(target_arch = "x86_64")]
            { hal_x86_64::pci::EcamPci::from_published().map(|r| pci::bridge_window_resources(&r, d.bdf)) }
            #[cfg(target_arch = "aarch64")]
            { hal_aarch64::pci::EcamPci::from_published().map(|r| pci::bridge_window_resources(&r, d.bdf)) }
        };
        for (index, window) in windows.unwrap_or([None; 3]).iter().enumerate() {
            if let Some(window) = window {
                resources.push(drv::Resource {
                    bar: (pci::uapi::BRIDGE_RESOURCE_INDEX + index) as u8,
                    start: window.start, end: window.end, flags: window.flags,
                });
            }
        }
    }
    resources
}

/// Enumerate the live PCI bus and emit a `[INFO] pci ...` line per
/// device under `debug-boot`. The PCI crate walks bridge windows; arch
/// setup still determines which config-space buses are addressable.
/// # SAFETY: caller is the boot path; per-arch ConfigSpaceReader
/// has been brought up and `ECAM_BASE_VA` published.
/// # C: O(N_bdfs probed)
pub fn enumerate_and_log() {
    config_access::install_hooks();
    let devs = scan_devices();
    debug_boot! {
        klog::write_raw(b"[INFO]  pci: devices=");
        klog::write_dec_u64(devs.len() as u64);
        klog::write_raw(b"\n");
    }
    let requesters = devs.iter().map(|d| d.bdf).collect::<alloc::vec::Vec<_>>();
    let aliases = dma_aliases(&requesters, &devs);
    if !activate_dma_and_interrupt_ownership(&requesters, &aliases) { return; }
    config_access::install_aml_region_backend();
    let _ = firmware::acpi::prepare_pci_intx_routes();
    pci_irq::set_intx_resolver(resolve_firmware_intx);
    register_pci_model_drivers();
    publish_scanned_devices(&devs);

    // F40 + F57: drain any MSIs queued during model probing through the
    // per-architecture IRQ dispatcher, then restore the boot-mask state.
    finish_probe_irq_window();

    // F59-15: install the default L2/netlink route state for every netdev
    // already registered by virtio-net's model probe.
    seed_boot_network_defaults();
}

#[inline(never)]
fn activate_dma_and_interrupt_ownership(requesters: &[pci::Bdf], aliases: &pci::DmaAliases) -> bool {
    quiesce_bus_masters(requesters);
    // Keep every quiesced requester denied until its DMA owner has attached it.
    // This policy must be visible before activation so a failed activation
    // cannot leave a later probe able to restore Bus Master by default.
    pci::set_bus_master_admission(Some(iommu::bus_master_admitted));
    // SAFETY: all discovered PCI requesters have been quiesced and no driver is registered yet.
    let iommu_activation = unsafe { iommu::activate_amd_vi(requesters, aliases,
        pmm::user_as::hhdm_offset(), pmm::setup::usable_regions()) };
    if iommu_activation == iommu::AmdViActivation::Failed { return false; }
    if iommu_activation == iommu::AmdViActivation::Enabled
        && !amd_vi_events::install(requesters) { return false; }
    let vtd_activation = activate_vtd_arch(requesters, aliases);
    if vtd_activation == iommu::VtdActivation::Failed { return false; }
    #[cfg(target_arch = "x86_64")]
    if vtd_activation == iommu::VtdActivation::Enabled && !vtd_faults::install() { return false; }
    if !iommu::enable_vtd_interrupt_remapping() { return false; }
    iommu::admit_boot_requesters(requesters);
    if !map_firmware_ioapics() { return false; }
    // Linux probes interrupt-driven PCI functions with local IRQ delivery
    // enabled.  Every requester remains bus-master quiesced until its driver
    // has installed a handler and explicitly admits DMA above.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the GIC is live and all unowned PCI requesters remain quiesced.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)); }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the LAPIC/IDT are live and all unowned PCI requesters remain quiesced.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    true
}

#[inline(never)]
fn publish_scanned_devices(devs: &[pci::PciDevice]) {
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
        #[cfg(feature = "debug-boot")]
        let bound = publish_scanned_device(d).and_then(|dev| dev.bound());
        #[cfg(not(feature = "debug-boot"))]
        let _ = publish_scanned_device(d);
        debug_boot! {
            klog::write_raw(b"[INFO]  pci driver=");
            klog::write_raw(bound.unwrap_or("none").as_bytes());
            klog::write_raw(b"\n");
        }
    }

}

#[inline(never)]
fn finish_probe_irq_window() {
    #[cfg(target_arch = "aarch64")]
    {
        for _ in 0..2_000_000 { core::hint::spin_loop(); }
        // SAFETY: privileged DAIF write at EL1, restoring the boot-mask state
        // this block opened two lines above; no scheduler runs yet.
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)); }
    }
    #[cfg(target_arch = "x86_64")]
    {
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
        // SAFETY: pairs with the pre-probe STI; restores boot-mask state.
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
    }
    debug_boot! {
        let fires = arch_irq::MSI_FIRES
            .load(core::sync::atomic::Ordering::Acquire);
        klog::write_raw(b"[INFO]  msi-fires-post-enum=");
        klog::write_dec_u64(fires as u64);
        klog::write_raw(b"\n");
    }

}

#[inline(never)]
fn seed_boot_network_defaults() {
    {
        let stack = net::sock::stack();
        let lo_idx = stack.ifaces.lookup_name("lo").map(|(id, _)| id.0);
        ::netlink::rtnetlink::seed_defaults(None, lo_idx);
        if let Some(lo_idx) = lo_idx {
            ::netlink::rtnetlink::seed_default_routes_lo(lo_idx);
        }
        for (_device_key, id) in drv_virtio_net::modern::registered_ifaces() {
            // NO address, mask or default route is seeded here.
            //
            // A kernel does not know its own IPv4 identity; a DHCP client
            // learns it. Installing the emulator's well-known guest address at
            // boot handed the network manager a link that already carried an
            // address and a default route it had not configured, and a manager
            // that finds a link configured behind its back marks it externally
            // connected and declines to own it. It then never runs its own
            // activation, so it never performs DHCP and never publishes the
            // DNS servers the lease would have carried — which is why
            // `/etc/resolv.conf` had no `nameserver` line at all and name
            // resolution failed while a query aimed straight at a server's
            // address still worked.
            //
            // The router solicitation stays: it is the kernel's own half of
            // IPv6 address autoconfiguration, which the reference also drives.
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

fn dma_aliases(requesters: &[pci::Bdf], devices: &[pci::PciDevice]) -> pci::DmaAliases {
    let mut aliases = pci::DmaAliases::new();
    for index in 0..firmware::acpi::amd_vi_alias_count() {
        let Some(record) = firmware::acpi::amd_vi_alias(index) else { continue; };
        let Some(unit) = firmware::acpi::iommu_unit(record.unit_index as usize) else { continue; };
        for requester in requesters.iter().copied().filter(|bdf| bdf.segment == unit.segment
            && bdf.raw() >= record.first_requester && bdf.raw() <= record.last_requester) {
            let canonical = pci::Bdf { segment: requester.segment, bus: (record.canonical_requester >> 8) as u8,
                device: ((record.canonical_requester >> 3) & 0x1f) as u8, function: (record.canonical_requester & 7) as u8 };
            if requesters.contains(&canonical) { let _ = aliases.add(requester, canonical); }
        }
    }
    #[cfg(target_arch = "x86_64")]
    if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() {
        let bridges = devices.iter().filter_map(|d| pci::bridge_buses(&reader, d.bdf).map(|b| (d.bdf, b)))
            .collect::<alloc::vec::Vec<_>>();
        pci::add_topology_dma_aliases(&mut aliases, requesters, &bridges,
            |bdf| pci::pcie_type(&reader, bdf));
    }
    #[cfg(target_arch = "aarch64")]
    if let Some(reader) = hal_aarch64::pci::EcamPci::from_published() {
        let bridges = devices.iter().filter_map(|d| pci::bridge_buses(&reader, d.bdf).map(|b| (d.bdf, b)))
            .collect::<alloc::vec::Vec<_>>();
        pci::add_topology_dma_aliases(&mut aliases, requesters, &bridges,
            |bdf| pci::pcie_type(&reader, bdf));
    }
    aliases
}

/// Walk every addressable config-space bus. # C: O(N_bdfs probed)
fn scan_devices() -> alloc::vec::Vec<pci::PciDevice> {
    #[cfg(target_arch = "x86_64")]
    {
        match hal_x86_64::pci::EcamPci::from_published() {
            Some(r) => r.windows().iter().flat_map(|w| pci::enumerate_segment_buses(
                &r, w.segment, w.bus_start, u16::from(w.bus_end) - u16::from(w.bus_start) + 1,
            )).collect(),
            None => alloc::vec::Vec::new(),
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        match hal_aarch64::pci::EcamPci::from_published() {
            Some(r) => r.windows().iter().flat_map(|w| pci::enumerate_segment_buses(
                &r, w.segment, w.bus_start, u16::from(w.bus_end) - u16::from(w.bus_start) + 1,
            )).collect(),
            None    => alloc::vec::Vec::new(),
        }
    }
}

/// Register one scanned function with the driver model. Already-registered
/// functions resolve to their live object, so a rescan only adds what appeared.
/// # C: O(N_devices)
fn publish_scanned_device(d: &pci::PciDevice) -> Option<alloc::sync::Arc<drv::Device>> {
    let class24 = ((d.class_code as u32) << 16)
        | ((d.subclass as u32) << 8) | (d.prog_if as u32);
    let addr = alloc::format!("{:04x}:{:02x}:{:02x}.{}",
        d.bdf.segment, d.bdf.bus, d.bdf.device, d.bdf.function);
    publish_pci_model_device(d, addr, class24)
}

/// Re-enumerate the PCI hierarchy and publish functions that appeared since
/// the last scan (sysfs `rescan`). # C: O(N_bdfs probed)
pub fn rescan() {
    for d in scan_devices().iter() {
        publish_scanned_device(d);
    }
}

/// Retry firmware-gated built-in PCI functions after the root filesystem is mounted.
/// # C: O(N_devices + probe)
pub fn retry_firmware_gated_drivers() {
    for dev in drv::devices() {
        if dev.bus == "pci" && dev.bound().is_none()
            && dev.vendor_id == drv_rtl8125::regs::VENDOR_REALTEK
            && dev.device_id == drv_rtl8125::regs::DEVICE_RTL8125 {
            let _ = drv::bind(&dev, "r8169");
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
            .with_pci_ident(config_access::pci_ident(d))
            .with_resources(pci_resources_arch(d)),
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
