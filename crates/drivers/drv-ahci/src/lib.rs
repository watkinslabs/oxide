// AHCI/SATA block driver (drivers-plan D3.6). A real HBA bring-up: GHC.AE →
// scan Ports Implemented → first port with a SATA disk (DET==3, SIG==0x101)
// → stop/program/start the port → ATA IDENTIFY → READ/WRITE DMA EXT via a
// PRDT bounce frame, exposed as a `block::BlockDevice` under Linux-style SCSI
// disk names `sda`, `sdb`, ... . The model driver's `probe` matches PCI class
// 0x010601 (QEMU ich9-ahci vendor 0x8086 device 0x2922), maps BAR5 (ABAR),
// and calls `init`.
//
// Layering: `regs.rs` = pure register/FIS/IDENTIFY math; `port.rs` = HBA/port
// lifecycle; `command.rs` = command DMA staging; `irq.rs` = MSI hard-handler
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
mod irq;
#[cfg(target_os = "oxide-kernel")]
mod port;
#[cfg(target_os = "oxide-kernel")]
mod wait;

#[cfg(target_os = "oxide-kernel")]
mod imp {
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};
    use sync::{Spinlock, TaskList as DriverLockClass};
    use block::BlockDevice;
    #[cfg(feature = "debug-boot")]
    use block::BlockRequest;
    use crate::device::AhciBlk;
    use crate::port::Ahci;

    /// PCI class for an AHCI controller: base 0x01 (mass storage), subclass
    /// 0x06 (SATA), prog-if 0x01 (AHCI 1.0). # C: O(1)
    pub const AHCI_CLASS24: u32 = 0x01_06_01;

    /// Global registration-order counter for Linux SCSI disk names.
    /// Each successfully-published AHCI disk claims the next `sdX` slot.
    static NEXT_DISK_INDEX: AtomicU32 = AtomicU32::new(0);

    struct AhciRecord {
        device_key: pci::Bdf,
        command_orig: u16,
        name:       String,
        dev:        Arc<AhciBlk>,
    }

    static DEVICES: Spinlock<Vec<AhciRecord>, DriverLockClass> = Spinlock::new(Vec::new());

    fn run_completion_bottom_half() {
        let devices: Vec<Arc<AhciBlk>> = DEVICES
            .lock()
            .iter()
            .map(|record| record.dev.clone())
            .collect();
        for dev in devices { dev.completion_bottom_half(); }
    }

    fn unregister_completion_if_idle() {
        if DEVICES.lock().is_empty() {
            let _ = block::completion::unregister(run_completion_bottom_half);
        }
    }

    #[cfg(feature = "debug-boot")]
    fn key_bus(key: pci::Bdf) -> u8 { key.bus }
    #[cfg(feature = "debug-boot")]
    fn key_device(key: pci::Bdf) -> u8 { key.device }
    #[cfg(feature = "debug-boot")]
    fn key_function(key: pci::Bdf) -> u8 { key.function }

    fn sd_name(index: u32) -> String {
        let mut out = [0u8; 8];
        out[0] = b's';
        out[1] = b'd';
        let mut suffix = [0u8; 6];
        let mut k = 0usize;
        let mut n = index as u64 + 1;
        while n > 0 && k < suffix.len() {
            n -= 1;
            suffix[k] = b'a' + (n % 26) as u8;
            k += 1;
            n /= 26;
        }
        let mut w = 2usize;
        while k > 0 && w < out.len() {
            k -= 1;
            out[w] = suffix[k];
            w += 1;
        }
        String::from_utf8_lossy(&out[..w]).into_owned()
    }

    pub fn device_key_from_bdf(bdf: pci::Bdf) -> pci::Bdf {
        bdf
    }

    /// Bring up the AHCI controller whose ABAR (BAR5) register file is mapped
    /// by `mmio` (≥2 pages), register the first SATA
    /// disk under a unique `sdX` name, and return the 1-based registry index
    /// (0 on failure). Optionally self-tests by reading LBA 0.
    /// # C: O(N_ahci + bring-up + registry O(N))
    pub fn init(
        device_key: pci::Bdf,
        command_orig: u16,
        mmio: mmio_map::Mapping,
        abar_off: u64,
    ) -> u32 {
        if DEVICES.lock().iter().any(|rec| rec.device_key == device_key) {
            return 0;
        }
        let mut a = match Ahci::bring_up(mmio, abar_off) { Ok(a) => a, Err(reason) => {
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
        let blk_size = a.blk_size;
        let capacity = a.sectors;
        let serial = a.serial.clone();

        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  ahci: port0 ready sectors=");
            klog::write_dec_u64(capacity);
            klog::write_raw(b" bsz=");
            klog::write_dec_u64(blk_size as u64);
            klog::write_raw(b"\n");
        }

        if !block::completion::register(run_completion_bottom_half) {
            a.shutdown_and_free();
            return 0;
        }
        let Some(binding) = crate::irq::bind(device_key, &a) else {
            a.shutdown_and_free();
            unregister_completion_if_idle();
            return 0;
        };
        let dev = Arc::new(AhciBlk::new(a, binding, blk_size, capacity));

        let block_dev: Arc<dyn BlockDevice> = dev.clone();
        let name = sd_name(NEXT_DISK_INDEX.fetch_add(1, Ordering::Relaxed));
        let existed = block::registry::by_name(&name).is_some();
        let idx = block::registry::register_with_driver(
            block::registry::BlockDriver::fixed("sd", block::uapi::SCSI_DISK_MAJOR), &name, serial.as_deref(), block_dev);
        let published = if idx != 0 && !existed {
            let mut devices = DEVICES.lock();
            if devices.iter().any(|rec| rec.device_key == device_key) {
                false
            } else {
                devices.push(AhciRecord {
                    device_key,
                    command_orig,
                    name: name.clone(),
                    dev: dev.clone(),
                });
                true
            }
        } else {
            false
        };
        if !published {
            if idx != 0 && !existed {
                let _ = block::registry::unregister(&name);
            }
            dev.remove();
            unregister_completion_if_idle();
            return 0;
        }
        // Run after DEVICES publication so the shared BlockIo bottom half can
        // find and wake this controller's completion waiter.
        #[cfg(feature = "debug-boot")]
        {
            let before = dev.irq_completion_count();
            let mut req = BlockRequest::new_read(0, 1, blk_size);
            let ok = dev.submit_sync(&mut req).is_ok();
            let irqs = dev.irq_completion_count().saturating_sub(before);
            klog::write_raw(b"[INFO]  ahci: lba0 read selftest=");
            klog::write_dec_u64(ok as u64);
            klog::write_raw(b" irq_completions=");
            klog::write_dec_u64(irqs);
            klog::write_raw(b"\n");
        }
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  ahci ");
            klog::write_dec_u64(key_bus(device_key) as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(key_device(device_key) as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(key_function(device_key) as u64);
            klog::write_raw(b" block dev registered idx=");
            klog::write_dec_u64(idx as u64);
            klog::write_raw(b"\n");
        }
        idx
    }

    /// Remove the registered AHCI disk and release controller-owned resources.
    /// # C: O(N_ahci + N_disks + port shutdown)
    pub fn remove(device_key: pci::Bdf) -> bool {
        let rec = {
            let mut devices = DEVICES.lock();
            match devices.iter().position(|rec| rec.device_key == device_key) {
                Some(i) => devices.remove(i),
                None => return false,
            }
        };
        let _ = block::registry::unregister(&rec.name);
        rec.dev.remove();
        unregister_completion_if_idle();
        true
    }

    /// Quiesce the bound AHCI controller for reboot/poweroff without
    /// unregistering userspace-visible block publication.
    /// # C: O(N_ahci + port shutdown)
    pub fn shutdown(device_key: pci::Bdf) -> bool {
        let dev = match DEVICES
            .lock()
            .iter()
            .find(|rec| rec.device_key == device_key)
            .map(|rec| rec.dev.clone())
        {
            Some(dev) => dev,
            None => return false,
        };
        dev.shutdown();
        true
    }

    /// Original PCI command bits saved before this driver enabled decode.
    /// # C: O(N_ahci)
    pub fn command_orig_for(device_key: pci::Bdf) -> Option<u16> {
        DEVICES
            .lock()
            .iter()
            .find(|rec| rec.device_key == device_key)
            .map(|rec| rec.command_orig)
    }
}

#[cfg(target_os = "oxide-kernel")]
pub use imp::{command_orig_for, device_key_from_bdf, init, remove, shutdown, AHCI_CLASS24};
#[cfg(target_os = "oxide-kernel")]
pub use device::AhciBlk;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn decode_bars(bdf: pci::Bdf) -> [pci::Bar; 6] {
    match hal_x86_64::pci::EcamPci::from_published() {
        Some(r) => pci::decode_bars(&r, bdf),
        None => [pci::Bar::None; 6],
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn decode_bars(bdf: pci::Bdf) -> [pci::Bar; 6] {
    match hal_aarch64::pci::EcamPci::from_published() {
        Some(r) => pci::decode_bars(&r, bdf),
        None => [pci::Bar::None; 6],
    }
}

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
        let bars = decode_bars(bdf);
        let abar_pa = bars[5].mem_base().unwrap_or(0);
        if abar_pa == 0 {
            restore_pci_bus_master(dev, command_orig);
            return Err(drv::Error::ProbeFailed);
        }
        // SAFETY: BAR5 PA came from this PCI function's config space; two
        // pages cover generic HBA registers plus the 32-port register array.
        let mmio = unsafe { mmio_map::map_owned(abar_pa & BAR_PAGE_BASE_MASK, 2) };
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
