// AHCI/SATA block driver (drivers-plan D3.6). A real HBA bring-up: GHC.AE →
// scan Ports Implemented → first port with a SATA disk (DET==3, SIG==0x101)
// → stop/program/start the port → ATA IDENTIFY → READ/WRITE DMA EXT via a
// contiguous PRDT DMA run, exposed as a `block::BlockDevice` under Linux-style SCSI
// disk names `sda`, `sdb`, ... . The model driver's `probe` matches PCI class
// 0x010601 (QEMU ich9-ahci vendor 0x8086 device 0x2922), maps BAR5 (ABAR),
// and calls `init`.
//
// Layering: `regs.rs` = pure register/FIS/IDENTIFY math; `port.rs` = HBA/port
// lifecycle; `host.rs` = HBA-wide ABAR/IRQ ownership; `command.rs` = command
// DMA staging; `irq.rs` = shared-MSI hard-handler
// endpoints; `wait.rs` = process wait mechanics; `device.rs` = BlockDevice;
// `lifecycle.rs` = hosted cleanup-order proof; this file = registration + PCI
// bring-up glue.

#![no_std]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;

mod regs;
#[cfg(any(target_os = "oxide-kernel", test))]
mod lifecycle;
#[cfg(target_os = "oxide-kernel")]
mod command;
#[cfg(target_os = "oxide-kernel")]
mod device;
#[cfg(target_os = "oxide-kernel")]
mod host;
#[cfg(target_os = "oxide-kernel")]
mod irq;
#[cfg(target_os = "oxide-kernel")]
mod port;
#[cfg(target_os = "oxide-kernel")]
mod wait;
#[cfg(target_os = "oxide-kernel")]
mod hotplug;

#[cfg(target_os = "oxide-kernel")]
pub(crate) mod imp {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use sync::{Spinlock, TaskList as DriverLockClass};
    use crate::device::AhciBlk;
    use crate::host::AhciHost;

    /// PCI class for an AHCI controller: base 0x01 (mass storage), subclass
    /// 0x06 (SATA), prog-if 0x01 (AHCI 1.0). # C: O(1)
    pub const AHCI_CLASS24: u32 = 0x01_06_01;

    pub(crate) struct AhciRecord {
        pub(crate) device_key: pci::Bdf,
        pub(crate) command_orig: u16,
        pub(crate) port:       u32,
        pub(crate) name:       block::ScsiDiskName,
        pub(crate) dev:        Arc<AhciBlk>,
    }

    pub(crate) static DEVICES: Spinlock<Vec<AhciRecord>, DriverLockClass> = Spinlock::new(Vec::new());
    use crate::hotplug::{self, run_completion_bottom_half, unregister_completion_if_idle};
/// Bottom-half gate for the completion/drain-softirq-shared lock: real
/// exclusion in the kernel, a no-op under hosted tests. Every acquisition of
/// the lock goes through `lock_bh`, softirq context included — the disable
/// counts and the enable drains only at the outermost level outside IRQ, i.e.
/// the reference `spin_lock_bh` nesting. A bare process-context hold is the
/// one-CPU deadlock B2007/B2008 fixed: the softirq spins on an owner it
/// interrupted.
#[cfg(target_os = "oxide-kernel")]
pub(crate) type AhciBh = sched::bh::SchedBh;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type AhciBh = sync::NoopBh;


    pub fn device_key_from_bdf(bdf: pci::Bdf) -> pci::Bdf {
        bdf
    }

    /// Bring up the AHCI controller whose ABAR (BAR5) register file is mapped
    /// by `mmio`, register every ready SATA disk under unique `sdX` names,
    /// and return the first 1-based registry index
    /// (0 on failure). Optionally self-tests by reading LBA 0.
    /// # C: O(N_ahci + bring-up + registry O(N))
    pub fn init(
        device_key: pci::Bdf,
        command_orig: u16,
        mmio: mmio_map::Mapping,
        abar_off: u64,
    ) -> u32 {
        if hotplug::controller_bound(device_key) {
            return 0;
        }
        let host = match AhciHost::bring_up(device_key, mmio, abar_off) { Ok(host) => Arc::new(host), Err(reason) => {
            // "no ..." = an empty HBA (e.g. the ICH9 chipset SATA controller
            // with no drive attached) — benign INFO, not a failure WARN.
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(if reason.starts_with("no ") { b"[INFO]  ahci: " }
                                else { b"[WARN]  ahci: " });
                klog::write_raw(reason.as_bytes());
                klog::write_raw(b"\n");
            }
            let _ = reason;
            return 0;
        }};
        if !block::completion::register(run_completion_bottom_half) {
            return 0;
        }
        let mut first_idx = 0u32;
        let mut bound = false;
        for port in 0..32 {
            if host.ports() & (1 << port) == 0 { continue; }
            if let Some(idx) = hotplug::publish_port(device_key, command_orig, host.clone(), port) {
                bound = true;
                if first_idx == 0 { first_idx = idx; }
                continue;
            }
            bound |= hotplug::install_watcher(device_key, command_orig, host.clone(), port);
        }
        if !bound {
            unregister_completion_if_idle();
            return 0;
        }
        first_idx.max(1)
    }

    /// Remove the registered AHCI disk and release controller-owned resources.
    /// # C: O(N_ahci + N_disks + port shutdown)
    pub fn remove(device_key: pci::Bdf) -> bool {
        let (records, watches) = hotplug::remove_controller(device_key);
        if records.is_empty() && watches.is_empty() { return false; }
        for rec in &records { let _ = block::registry::unregister(rec.name.as_str()); }
        for rec in records.into_iter().rev() { rec.dev.remove(); }
        for watch in watches.into_iter().rev() { watch.release(); }
        unregister_completion_if_idle();
        true
    }

    /// Quiesce the bound AHCI controller for reboot/poweroff without
    /// unregistering userspace-visible block publication.
    /// # C: O(N_ahci + port shutdown)
    pub fn shutdown(device_key: pci::Bdf) -> bool {
        let devices: Vec<Arc<AhciBlk>> = DEVICES
            .lock_bh::<AhciBh>()
            .iter()
            .filter(|rec| rec.device_key == device_key)
            .map(|rec| rec.dev.clone())
            .collect();
        let (_records, watches) = hotplug::remove_controller(device_key);
        if devices.is_empty() && watches.is_empty() { return false; }
        for dev in devices.into_iter().rev() { dev.shutdown(); }
        for watch in watches.into_iter().rev() { watch.release(); }
        unregister_completion_if_idle();
        true
    }

    /// Original PCI command bits saved before this driver enabled decode.
    /// # C: O(N_ahci)
    pub fn command_orig_for(device_key: pci::Bdf) -> Option<u16> {
        hotplug::controller_command_orig(device_key)
    }
}

#[cfg(target_os = "oxide-kernel")]
pub use imp::{command_orig_for, device_key_from_bdf, init, remove, shutdown, AHCI_CLASS24};
#[cfg(target_os = "oxide-kernel")]
pub use device::AhciBlk;

#[cfg(target_os = "oxide-kernel")]
fn restore_pci_bus_master(dev: &drv::Device, command_orig: u16) {
    let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return; };
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
            let _ = pci::restore_mem_bus_master(&r, bdf, command_orig);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let _ = pci::restore_mem_bus_master(&r, bdf, command_orig);
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
const BAR_PAGE_SIZE: u64 = 0x1000;
#[cfg(target_os = "oxide-kernel")]
const BAR_PAGE_OFFSET_MASK: u64 = BAR_PAGE_SIZE - 1;
#[cfg(target_os = "oxide-kernel")]
const BAR_PAGE_BASE_MASK: u64 = !BAR_PAGE_OFFSET_MASK;

/// The D1a model driver for AHCI: matches PCI class 0x010601 on the PCI bus.
/// Registered + bound at the bring-up success site in pci-boot.
#[cfg(target_os = "oxide-kernel")]
pub struct AhciDriver;

#[cfg(target_os = "oxide-kernel")]
impl drv::Driver for AhciDriver {
    fn name(&self) -> &'static str { "ahci" }
    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "pci" && dev.class == imp::AHCI_CLASS24
    }

    fn probe(&self, dev: &alloc::sync::Arc<drv::Device>) -> drv::KResult<()> {
        let bdf = pci::parse_bdf_addr(&dev.addr).ok_or(drv::Error::ProbeFailed)?;
        #[cfg(target_arch = "x86_64")]
        let command_orig = {
            if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
                pci::enable_mem_bus_master(&r, bdf)
            } else {
                return Err(drv::Error::ProbeFailed);
            }
        };
        #[cfg(target_arch = "aarch64")]
        let command_orig = {
            if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
                pci::enable_mem_bus_master(&r, bdf)
            } else {
                return Err(drv::Error::ProbeFailed);
            }
        };
        let Some(resource) = dev.resources.iter().find(|resource| resource.bar == 5 && resource.flags & drv::IORESOURCE_MEM != 0) else {
            restore_pci_bus_master(dev, command_orig);
            return Err(drv::Error::ProbeFailed);
        };
        let abar_pa = resource.start;
        let bar_bytes = resource.end.checked_sub(resource.start).and_then(|bytes| bytes.checked_add(1)).ok_or(drv::Error::ProbeFailed)?;
        let map_bytes = (abar_pa & BAR_PAGE_OFFSET_MASK).checked_add(bar_bytes).ok_or(drv::Error::ProbeFailed)?;
        let pages = map_bytes.checked_add(BAR_PAGE_OFFSET_MASK).and_then(|bytes| bytes.checked_div(BAR_PAGE_SIZE)).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: BAR5 was enumerated for this AHCI function; this mapping owns its complete page-rounded aperture.
        let mmio = unsafe { mmio_map::map_owned(abar_pa & BAR_PAGE_BASE_MASK, pages) };
        let device_key = imp::device_key_from_bdf(bdf);
        if imp::init(device_key, command_orig, mmio, abar_pa & BAR_PAGE_OFFSET_MASK) == 0 {
            lifecycle::run_probe_failure_cleanup(|| restore_pci_bus_master(dev, command_orig));
            return Err(drv::Error::ProbeFailed);
        }
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return; };
        let command_orig = imp::command_orig_for(imp::device_key_from_bdf(bdf));
        lifecycle::run_remove_cleanup(
            || { let _ = imp::remove(imp::device_key_from_bdf(bdf)); },
            || { if let Some(command_orig) = command_orig { restore_pci_bus_master(dev, command_orig); } },
        );
    }

    fn shutdown(&self, dev: &drv::Device) {
        let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return; };
        let command_orig = imp::command_orig_for(imp::device_key_from_bdf(bdf));
        lifecycle::run_remove_cleanup(
            || { let _ = imp::shutdown(imp::device_key_from_bdf(bdf)); },
            || { if let Some(command_orig) = command_orig { restore_pci_bus_master(dev, command_orig); } },
        );
    }
}

/// Singleton driver instance for registration. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub static AHCI_DRIVER: AhciDriver = AhciDriver;
