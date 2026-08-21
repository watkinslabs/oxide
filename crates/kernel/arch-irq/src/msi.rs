//! Architecture-owned PCI MSI message allocation.
//!
//! PCI drivers supply requester/event identity; this module owns APIC vector,
//! GICv2m SPI, and GICv3 ITS/LPI allocation plus handler lifecycle.

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// One architecture-routed MSI/MSI-X message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsiMessage {
    pub irq:     u32,
    pub address: u64,
    pub data:    u32,
}

#[cfg(target_arch = "x86_64")]
const X86_APIC_MSI_ADDRESS: u64 = 0xFEE0_0000;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn x86_bsp_apic_id() -> u32 { crate::lapic::local_apic_id() }
#[cfg(all(target_arch = "x86_64", not(target_os = "oxide-kernel")))]
const fn x86_bsp_apic_id() -> u32 { 0 }

#[cfg(target_arch = "x86_64")]
const fn direct_x86_msi(vector: u8, destination: u32) -> Option<MsiMessage> {
    if destination > u8::MAX as u32 { return None; }
    Some(MsiMessage { irq: vector as u32, address: X86_APIC_MSI_ADDRESS | ((destination as u64) << 12), data: vector as u32 })
}

#[cfg(target_arch = "x86_64")]
const fn vtd_x86_msi(vector: u8, destination: u32) -> MsiMessage {
    MsiMessage { irq: vector as u32, address: X86_APIC_MSI_ADDRESS | (((destination & 0xff) as u64) << 12)
        | (((destination >> 8) as u64) << 32), data: vector as u32 }
}

/// Allocate a direct architecture MSI for a non-PCI interrupt source. # C: O(N_irq_slots)
pub fn request_platform_msi(action: crate::irqstat::DeviceAction, handler: fn()) -> Option<MsiMessage> {
    #[cfg(target_arch = "x86_64")]
    {
        let vector = super::alloc_x86_vector()?;
        if super::register_msi_handler(vector, handler).is_err()
            || !crate::irqstat::register_msi(vector as u32, action) {
            let _ = super::free_x86_vector(vector);
            return None;
        }
        let _ = crate::msi_suspend::install(vector as u32);
        return Some(vtd_x86_msi(vector, x86_bsp_apic_id()));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (action, handler);
        None
    }
}

/// Withdraw a non-PCI architecture MSI after its producer is masked. # C: O(1)
pub fn free_platform_msi(message: MsiMessage) {
    crate::msi_suspend::uninstall(message.irq);
    crate::irqstat::unregister_msi(message.irq);
    #[cfg(target_arch = "x86_64")]
    if let Ok(vector) = u8::try_from(message.irq) { let _ = super::free_x86_vector(vector); }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = message;
}

/// Allocate one PCI message for `requester` and device-local `event_id`.
/// # C: O(N_irq_slots)
pub fn alloc_pci_msi(requester: pci::Bdf, event_id: u32) -> Option<MsiMessage> {
    #[cfg(target_arch = "x86_64")]
    {
        let vector = super::alloc_x86_vector()?;
        let destination = x86_bsp_apic_id();
        match iommu::allocate_amd_vi_msi(requester, event_id, vector, destination) {
            iommu::AmdViMsi::Remapped { address, data } => return Some(MsiMessage { irq: vector as u32, address, data }),
            iommu::AmdViMsi::Failed => { let _ = super::free_x86_vector(vector); return None; }
            iommu::AmdViMsi::Direct => {}
        }
        match iommu::allocate_vtd_msi(requester, vector, destination) {
            iommu::VtdMsi::Remapped { address, data } => return Some(MsiMessage { irq: vector as u32, address, data }),
            iommu::VtdMsi::Failed => { let _ = super::free_x86_vector(vector); return None; }
            iommu::VtdMsi::Direct => {}
        }
        let _ = event_id;
        return match direct_x86_msi(vector, destination) {
            Some(message) => Some(message), None => { let _ = super::free_x86_vector(vector); None }
        };
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let requester_id = ((requester.bus as u32) << 8) | ((requester.device as u32) << 3) | requester.function as u32;
        return arm::alloc(requester_id, event_id);
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "oxide-kernel")
    )))]
    {
        let _ = (requester, event_id);
        None
    }
}

/// Install the hard handler for one allocated PCI message.
/// # C: O(N_irq_slots)
pub fn register_pci_msi_handler(irq: u32, action: crate::irqstat::DeviceAction, handler: fn()) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let installed = u8::try_from(irq)
            .ok()
            .is_some_and(|vector| super::register_msi_handler(vector, handler).is_ok());
        if installed {
            let _ = crate::irqstat::register_msi(irq, action);
            let _ = crate::msi_suspend::install(irq);
        }
        return installed;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let installed = super::register_msi_handler(irq, handler).is_ok();
        if installed {
            let _ = crate::irqstat::register_msi(irq, action);
            let _ = crate::msi_suspend::install(irq);
        }
        return installed;
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (irq, action, handler);
        false
    }
}

/// Install one PCI MSI handler with the binding-owned context argument.
/// # C: O(N_irq_slots)
pub fn register_pci_msi_context_handler(irq: u32, action: crate::irqstat::DeviceAction,
    handler: fn(usize), arg: usize) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let installed = u8::try_from(irq).ok().is_some_and(|vector|
            super::msi_context::register_x86(vector, handler, arg).is_ok());
        if installed {
            let _ = crate::irqstat::register_msi(irq, action);
            let _ = crate::msi_suspend::install(irq);
        }
        return installed;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let installed = super::msi_context::register_arm(irq, handler, arg).is_ok();
        if installed {
            let _ = crate::irqstat::register_msi(irq, action);
            let _ = crate::msi_suspend::install(irq);
        }
        return installed;
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = (irq, action, handler, arg); false }
}

/// Remove the handler and release one PCI message ID.
/// # C: O(N_irq_slots)
pub fn free_pci_msi(irq: u32) {
    crate::msi_suspend::uninstall(irq);
    crate::irqstat::unregister_msi(irq);
    #[cfg(target_arch = "x86_64")]
    if let Ok(vector) = u8::try_from(irq) {
        let _ = super::free_x86_vector(vector);
    }
    #[cfg(target_arch = "aarch64")]
    {
        arm::forget_lpi_route(irq);
        let _ = super::free_arm_spi(irq);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = irq;
}

/// Dispatch the handler owned by one x86 MSI vector without re-entering the
/// lifecycle admission path (used by IRQ entry and pending replay). # C: O(1)
#[cfg(target_arch = "x86_64")]
pub(crate) fn invoke_x86_owned(irq: u32) -> bool {
    let Ok(vector) = u8::try_from(irq) else { return false; };
    if crate::msi_context::invoke_x86(vector) { return true; }
    if vector < hal_x86_64::VEC_MSI_POOL_FIRST || vector > hal_x86_64::VEC_MSI_POOL_LAST {
        return false;
    }
    let index = (vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    let raw = crate::MSI_HANDLERS[index].load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() { return false; }
    // SAFETY: register_msi_handler stored an ABI-compatible `fn()` here.
    let handler: fn() = unsafe { core::mem::transmute(raw) };
    handler();
    true
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod arm {
    use super::*;
    use sync::{Devices, Spinlock};

    const GICV2M_SETSPI_NSR_OFFSET: u64 = 0x40;
    const ITS_DEVICE_SLOTS: usize = 32;
    const ITS_ITT_FRAME_BYTES: usize = 0x1000;
    const ITS_ITT_WORD_BYTES: usize = core::mem::size_of::<u64>();
    const ITS_ITT_EVENT_COUNT: u32 = 16;
    const ITS_BOOT_COLLECTION: u16 = 0;
    const ITS_BOOT_RDBASE: u32 = 0;
    const ITS_DEVICE_EMPTY: u32 = u32::MAX;

    static DEVICE_IDS: [AtomicU32; ITS_DEVICE_SLOTS] =
        [const { AtomicU32::new(ITS_DEVICE_EMPTY) }; ITS_DEVICE_SLOTS];
    static DEVICE_ITTS: [AtomicU64; ITS_DEVICE_SLOTS] =
        [const { AtomicU64::new(0) }; ITS_DEVICE_SLOTS];
    const LPI_ROUTE_EMPTY: u64 = u64::MAX;
    static LPI_ROUTES: [AtomicU64; super::super::ARM_MSI_SLOTS] =
        [const { AtomicU64::new(LPI_ROUTE_EMPTY) }; super::super::ARM_MSI_SLOTS];
    static ITS_COMMANDS: Spinlock<(), Devices> = Spinlock::new(());

    pub(super) fn alloc(requester_id: u32, event_id: u32) -> Option<MsiMessage> {
        if let Some(message) = alloc_its(requester_id, event_id) {
            return Some(message);
        }
        let spi = super::super::alloc_arm_spi()?;
        // SAFETY: SPI was allocated from arch-irq's GICv2m MSI range.
        unsafe { super::super::gic::enable_intid(spi); }
        let frame = firmware::acpi::GIC_MSI_FRAME_PA.load(Ordering::Acquire);
        if frame == 0 {
            let _ = super::super::free_arm_spi(spi);
            return None;
        }
        Some(MsiMessage {
            irq: spi,
            address: frame + GICV2M_SETSPI_NSR_OFFSET,
            data: spi,
        })
    }

    fn alloc_its(requester_id: u32, event_id: u32) -> Option<MsiMessage> {
        if event_id >= ITS_ITT_EVENT_COUNT { return None; }
        // Linux serializes every post against the ITS command queue; a device
        // probe can run after interrupt enable and must not assume boot's
        // single-CPU command context still exists.
        let _commands = ITS_COMMANDS.lock();
        let address = super::super::its::translater_pa();
        if address == 0 { return None; }
        let device_id = firmware::acpi::iort_msi_device_id(requester_id)
            .unwrap_or(requester_id);
        ensure_device(device_id)?;
        let lpi = super::super::alloc_arm_lpi()?;
        let hhdm = hal_aarch64::mmu_ops::hhdm_offset();
        // SAFETY: lpis_enable published the property table and HHDM maps it.
        let prop_ok = unsafe {
            super::super::gic::lpi_set_config(
                hhdm,
                lpi,
                super::super::gic::LPI_PROP_DEFAULT,
            )
        };
        if !prop_ok {
            let _ = super::super::free_arm_spi(lpi);
            return None;
        }
        let mapti = super::super::its::cmd_mapti(
            device_id,
            event_id,
            lpi,
            ITS_BOOT_COLLECTION,
        );
        // SAFETY: ITS is enabled and ensure_device installed this device's ITT.
        if !cmd_ok(unsafe { super::super::its::cmd_post(hhdm, mapti) }) {
            let _ = super::super::free_arm_spi(lpi);
            return None;
        }
        // SAFETY: MAPTI was posted above; INV/SYNC use the same command queue.
        let inv_ok = cmd_ok(unsafe {
            super::super::its::cmd_post(
                hhdm,
                super::super::its::cmd_inv(device_id, event_id),
            )
        });
        // SAFETY: MAPTI was posted above; SYNC targets the boot collection.
        let sync_ok = cmd_ok(unsafe {
            super::super::its::cmd_post(
                hhdm,
                super::super::its::cmd_sync(ITS_BOOT_RDBASE),
            )
        });
        if !inv_ok || !sync_ok {
            let _ = super::super::free_arm_spi(lpi);
            return None;
        }
        if !remember_lpi_route(lpi, device_id, event_id) {
            let _ = super::super::free_arm_spi(lpi);
            return None;
        }
        Some(MsiMessage { irq: lpi, address, data: event_id })
    }

    fn lpi_slot(lpi: u32) -> Option<usize> {
        super::super::ARM_MSI_SPIS.iter().position(|slot|
            slot.load(Ordering::Acquire) == lpi)
    }

    fn remember_lpi_route(lpi: u32, device_id: u32, event_id: u32) -> bool {
        let Some(slot) = lpi_slot(lpi) else { return false; };
        LPI_ROUTES[slot].store((u64::from(device_id) << 32) | u64::from(event_id),
            Ordering::Release);
        true
    }

    pub(super) fn forget_lpi_route(lpi: u32) {
        if let Some(slot) = lpi_slot(lpi) {
            LPI_ROUTES[slot].store(LPI_ROUTE_EMPTY, Ordering::Release);
        }
    }

    pub(super) fn set_lpi_enabled(lpi: u32, enabled: bool) -> bool {
        let Some(slot) = lpi_slot(lpi) else { return false; };
        let route = LPI_ROUTES[slot].load(Ordering::Acquire);
        if route == LPI_ROUTE_EMPTY { return false; }
        let device_id = (route >> 32) as u32;
        let event_id = route as u32;
        let _commands = ITS_COMMANDS.lock();
        let hhdm = hal_aarch64::mmu_ops::hhdm_offset();
        let config = if enabled { super::super::gic::LPI_PROP_DEFAULT }
            else { super::super::gic::LPI_PROP_DEFAULT & !super::super::gic::LPI_PROP_ENABLED };
        // SAFETY: the route was published only after this LPI's property table
        // entry and ITS DeviceID/EventID mapping became live.
        if !unsafe { super::super::gic::lpi_set_config(hhdm, lpi, config) } { return false; }
        // SAFETY: the command lock serializes the live ITS queue; this route's
        // mapping remains owned until free_pci_msi clears it.
        let inv = unsafe { super::super::its::cmd_post(hhdm,
            super::super::its::cmd_inv(device_id, event_id)) };
        // SAFETY: the same serialized queue targets the boot collection that
        // owns every currently allocated physical LPI.
        let sync = unsafe { super::super::its::cmd_post(hhdm,
            super::super::its::cmd_sync(ITS_BOOT_RDBASE)) };
        cmd_ok(inv) && cmd_ok(sync)
    }

    fn ensure_device(device_id: u32) -> Option<()> {
        for i in 0..ITS_DEVICE_SLOTS {
            if DEVICE_IDS[i].load(Ordering::Acquire) == device_id {
                return (DEVICE_ITTS[i].load(Ordering::Acquire) != 0).then_some(());
            }
        }
        for i in 0..ITS_DEVICE_SLOTS {
            if DEVICE_IDS[i]
                .compare_exchange(ITS_DEVICE_EMPTY, device_id, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            let itt_pa = match pmm::setup::alloc_raw_frame() {
                Some(pa) => pa,
                None => {
                    DEVICE_IDS[i].store(ITS_DEVICE_EMPTY, Ordering::Release);
                    return None;
                }
            };
            let hhdm = hal_aarch64::mmu_ops::hhdm_offset();
            if hhdm != 0 {
                // SAFETY: freshly allocated ITT frame is HHDM mapped and aligned.
                unsafe {
                    let p = hhdm.wrapping_add(itt_pa) as *mut u64;
                    for n in 0..(ITS_ITT_FRAME_BYTES / ITS_ITT_WORD_BYTES) {
                        core::ptr::write_volatile(p.add(n), 0);
                    }
                }
                super::super::cache::clean_to_poc(
                    hhdm.wrapping_add(itt_pa),
                    ITS_ITT_FRAME_BYTES,
                );
            }
            let Some(mapd) = super::super::its::cmd_mapd(
                device_id,
                itt_pa,
                ITS_ITT_EVENT_COUNT,
            ) else {
                // SAFETY: this freshly allocated frame was not published to the ITS.
                unsafe { pmm::setup::free_one_frame(itt_pa); }
                DEVICE_IDS[i].store(ITS_DEVICE_EMPTY, Ordering::Release);
                return None;
            };
            // SAFETY: zeroed aligned ITT remains owned until MAPD completes.
            if !cmd_ok(unsafe { super::super::its::cmd_post(hhdm, mapd) }) {
                // SAFETY: failed MAPD did not publish this ITT to hardware.
                unsafe { pmm::setup::free_one_frame(itt_pa); }
                DEVICE_IDS[i].store(ITS_DEVICE_EMPTY, Ordering::Release);
                return None;
            }
            // SAFETY: MAPD was posted above; SYNC targets the boot RDbase.
            let mapd_sync_ok = cmd_ok(unsafe {
                super::super::its::cmd_post(
                    hhdm,
                    super::super::its::cmd_sync(ITS_BOOT_RDBASE),
                )
            });
            if !mapd_sync_ok {
                // SAFETY: failed synchronization did not publish local ownership.
                unsafe { pmm::setup::free_one_frame(itt_pa); }
                DEVICE_IDS[i].store(ITS_DEVICE_EMPTY, Ordering::Release);
                return None;
            }
            DEVICE_ITTS[i].store(itt_pa, Ordering::Release);
            return Some(());
        }
        None
    }

    fn cmd_ok(status: super::super::its::CmdStatus) -> bool {
        matches!(status, super::super::its::CmdStatus::Posted { .. })
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
/// Toggle the parent controller for one allocated ARM MSI. # C: O(1)
pub(crate) fn set_arm_irq_enabled(irq: u32, enabled: bool) -> bool {
    if arm_msi_is_lpi(irq) { return arm::set_lpi_enabled(irq, enabled); }
    // SAFETY: an allocated non-LPI ARM MSI is a GICv2m SPI owned by this
    // descriptor; its Distributor line is the correct parent controller.
    unsafe {
        if enabled { crate::gic::enable_intid(irq); }
        else { crate::gic::disable_intid(irq); }
    }
    true
}

#[cfg(any(test, target_arch = "aarch64"))]
const fn arm_msi_is_lpi(irq: u32) -> bool { irq >= crate::gicdef::LPI_BASE }

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{alloc_pci_msi, direct_x86_msi, free_pci_msi, vtd_x86_msi, MsiMessage, X86_APIC_MSI_ADDRESS};

    #[test]
    fn direct_and_vtd_msi_preserve_their_distinct_destination_encodings() {
        assert_eq!(direct_x86_msi(0x51, 0x2a), Some(MsiMessage { irq: 0x51,
            address: X86_APIC_MSI_ADDRESS | 0x2a000, data: 0x51 }));
        assert_eq!(direct_x86_msi(0x51, 0x100), None);
        assert_eq!(vtd_x86_msi(0x51, 0xab12_3456), MsiMessage { irq: 0x51,
            address: 0x00ab_1234_fee5_6000, data: 0x51 });
    }

    #[test]
    fn arm_lpis_never_enter_the_distributor_spi_register_path() {
        assert!(!super::arm_msi_is_lpi(crate::gicdef::MAX_SHARED_INTID));
        assert!(super::arm_msi_is_lpi(crate::gicdef::LPI_BASE));
        assert!(super::arm_msi_is_lpi(crate::gicdef::LPI_BASE + 31));
    }

    #[test]
    fn x86_allocator_exposes_the_entire_vector_pool() {
        let mut messages: [Option<MsiMessage>; hal_x86_64::VEC_MSI_POOL_LEN] =
            [None; hal_x86_64::VEC_MSI_POOL_LEN];

        for (event_id, slot) in messages.iter_mut().enumerate() {
            let message = alloc_pci_msi(pci::Bdf { segment: 0, bus: 0x12, device: 6, function: 4 }, event_id as u32)
                .expect("one message per advertised vector");
            assert_eq!(message.address, X86_APIC_MSI_ADDRESS);
            assert_eq!(message.irq, u32::from(hal_x86_64::VEC_MSI_POOL_FIRST)
                + event_id as u32);
            assert_eq!(message.data, message.irq);
            *slot = Some(message);
        }
        assert_eq!(alloc_pci_msi(pci::Bdf { segment: 0, bus: 0x12, device: 6, function: 4 }, messages.len() as u32), None);

        for message in messages.into_iter().flatten() {
            free_pci_msi(message.irq);
        }
    }
}
