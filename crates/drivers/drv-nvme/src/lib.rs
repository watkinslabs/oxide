// NVMe block driver (drivers-plan D3.5). A real controller bring-up: reset →
// admin SQ/CQ → active-namespace discovery + IDENTIFY → one I/O queue pair →
// READ/WRITE via a PRP bounce frame, exposed as a `block::BlockDevice` under
// Linux-style registry names `nvme0n1`, `nvme1n1`, ... . The model driver's
// `probe` matches PCI class
// 0x010802 (QEMU vendor 0x1b36 device 0x0010), maps BAR0, and calls `init`.
//
// Layering: `regs.rs` = pure register/bit math (host-tested); `queue.rs` =
// the kernel-only MMIO + queue mechanics (the `Nvme` controller);
// `lifecycle.rs` = hosted cleanup-order proof; `imp/request.rs` = owned block
// request posting/completion; this file = registration + PCI bring-up glue.

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
#[cfg(any(target_os = "oxide-kernel", test))]
mod irq;
#[cfg(target_os = "oxide-kernel")]
mod platform;
#[cfg(target_os = "oxide-kernel")]
mod queue;
#[cfg(target_os = "oxide-kernel")]
mod wait;

#[cfg(target_os = "oxide-kernel")]
mod imp {
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use sync::{Spinlock, TaskList as DriverLockClass};
    use block::{BlockCompletion, BlockDevice, BlockRequest, BlockError, BlockOp, KResult};
    use crate::irq::IrqBinding;
    use crate::queue::Nvme;
    use crate::regs;
    use crate::wait;

    mod device;
    mod request;
    mod reset;
    mod watchdog;

    /// PCI class for an NVMe controller: base 0x01 (mass storage), subclass
    /// 0x08 (non-volatile memory), prog-if 0x02 (NVMe). # C: O(1)
    pub const NVME_CLASS24: u32 = 0x01_08_02;

    /// The registered block namespace: controller queue mechanics plus the
    /// one owned CID-indexed request state for that hardware queue.
    pub struct NvmeBlk {
        ctrl:     Spinlock<Nvme, DriverLockClass>,
        requests: Spinlock<request::Requests, DriverLockClass>,
        irq:      IrqBinding,
        blk_size: u32,
        capacity: u64,
        removed:  AtomicBool,
        poisoned: AtomicBool,
        resetting: AtomicBool,
    }

    impl NvmeBlk {
        /// Remove publication before calling this, then quiesce hardware and
        /// release queue/PRP frames. Existing Arc holders observe EIO.
        /// # C: O(controller shutdown + PMM frees)
        fn remove(&self) {
            self.quiesce_and_free();
        }

        /// Quiesce for reboot/poweroff without unregistering the block device.
        /// Existing Arc holders observe EIO while userspace publication stays
        /// intact for the terminal power transition.
        /// # C: O(controller shutdown + PMM frees)
        fn shutdown(&self) {
            self.quiesce_and_free();
        }

        fn quiesce_and_free(&self) {
            if self.removed.swap(true, Ordering::AcqRel) { return; }
            self.irq.begin_release();
            self.irq.synchronize_and_release();
            self.fail_owned_requests();
            self.ctrl.lock().shutdown_and_free();
        }
    }

    /// Global registration-order counter for Linux-style disk naming.
    /// Each successfully-published namespace claims the next controller index.
    static NEXT_DISK_INDEX: AtomicU32 = AtomicU32::new(0);

    struct NvmeRecord {
        device_key: pci::Bdf,
        command_orig: u16,
        name:       String,
        nsid:       u32,
        dev:        Arc<NvmeBlk>,
    }

    static DEVICES: Spinlock<Vec<NvmeRecord>, DriverLockClass> = Spinlock::new(Vec::new());
    #[cfg(target_os = "oxide-kernel")]
    type NvmeBh = sched::bh::SchedBh;

    fn run_completion_bottom_half() {
        let devices: Vec<Arc<NvmeBlk>> = DEVICES.lock_bh::<NvmeBh>()
            .iter().map(|record| record.dev.clone()).collect();
        for dev in devices { dev.completion_bottom_half(); }
    }

    fn unregister_completion_if_idle() {
        if DEVICES.lock_bh::<NvmeBh>().is_empty() {
            let _ = block::completion::unregister(run_completion_bottom_half);
        }
    }

    #[cfg(feature = "debug-boot")]
    fn key_bus(key: pci::Bdf) -> u8 { key.bus }
    #[cfg(feature = "debug-boot")]
    fn key_device(key: pci::Bdf) -> u8 { key.device }
    #[cfg(feature = "debug-boot")]
    fn key_function(key: pci::Bdf) -> u8 { key.function }

    fn nvme_name(index: u32, nsid: u32) -> String {
        alloc::format!("nvme{}n{}", index, nsid)
    }

    pub fn device_key_from_bdf(bdf: pci::Bdf) -> pci::Bdf {
        bdf
    }

    /// Bring up the NVMe controller mapped by `mmio` (BAR0 register file,
    /// ≥2 pages), register it under a unique `nvmeXn1` name, and return the
    /// 1-based registry index (0 on failure). Optionally self-tests by reading
    /// LBA 0. # C: O(N_nvme + controller bring-up + N_disks)
    pub fn init(
        device_key: pci::Bdf,
        command_orig: u16,
        vendor_id: u16,
        device_id: u16,
        mmio: mmio_map::Mapping,
        bar0_off: u64,
    ) -> u32 {
        if DEVICES.lock_bh::<NvmeBh>().iter().any(|rec| rec.device_key == device_key) {
            return 0;
        }
        if !block::completion::register(run_completion_bottom_half) { return 0; }
        let Some(irq) = crate::irq::bind(device_key, &mmio, bar0_off) else {
            unregister_completion_if_idle();
            return 0;
        };
        let nv = match Nvme::bring_up(device_key, regs::dma_mask(vendor_id, device_id), mmio, bar0_off, irq.vector()) { Some(n) => n, None => {
            irq.begin_release();
            irq.synchronize_and_release();
            unregister_completion_if_idle();
            #[cfg(feature = "debug-boot")]
            { klog::write_raw(b"[WARN]  nvme: controller bring-up failed\n"); }
            return 0;
        }};
        let (cq_pa, cq_head, cq_phase) = nv.io_cq_cursor();
        irq.configure_cq(cq_pa, cq_head, cq_phase);
        let nsid = nv.namespace_id();
        let blk_size = nv.blk_size;
        let capacity = nv.ns_blocks;

        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  nvme: ctrl ready ns blocks=");
            klog::write_dec_u64(capacity);
            klog::write_raw(b" bsz=");
            klog::write_dec_u64(blk_size as u64);
            klog::write_raw(b"\n");
        }

        let dev = Arc::new(NvmeBlk {
            ctrl: Spinlock::new(nv),
            requests: Spinlock::new(request::Requests::new()),
            irq,
            blk_size, capacity,
            removed: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            resetting: AtomicBool::new(false),
        });

        let name = nvme_name(NEXT_DISK_INDEX.fetch_add(1, Ordering::Relaxed), nsid);
        let existed = block::registry::by_name(&name).is_some();
        let idx = block::registry::register_with_driver(
            block::registry::BlockDriver::fixed("nvme", block::uapi::NVME_BLK_MAJOR), &name,
            Some("oxnvme"),
            dev.clone() as Arc<dyn BlockDevice>,
        );
        let published = if idx != 0 && !existed {
            let mut devices = DEVICES.lock_bh::<NvmeBh>();
            if devices.iter().any(|rec| rec.device_key == device_key) {
                false
            } else {
                devices.push(NvmeRecord {
                    device_key,
                    command_orig,
                    name: name.clone(),
                    nsid,
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
        watchdog::register();
        // The completion softirq finds its waiter through DEVICES, so run the
        // optional end-to-end read only after publication.
        #[cfg(feature = "debug-boot")]
        {
            let mut req = BlockRequest::new_read(0, 1, blk_size);
            let ok = dev.submit_sync(&mut req).is_ok();
            klog::write_raw(b"[INFO]  nvme: lba0 read selftest=");
            klog::write_dec_u64(ok as u64);
            klog::write_raw(b"\n");
        }
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  nvme ");
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

    /// Remove the registered NVMe disk and release controller-owned resources.
    /// # C: O(N_nvme + N_disks + controller shutdown)
    pub fn remove(device_key: pci::Bdf) -> bool {
        let rec = {
            let mut devices = DEVICES.lock_bh::<NvmeBh>();
            match devices.iter().position(|rec| rec.device_key == device_key) {
                Some(i) => devices.remove(i),
                None => return false,
            }
        };
        let _ = block::registry::unregister(&rec.name);
        rec.dev.remove();
        watchdog::unregister_if_idle();
        true
    }

    /// Quiesce the bound NVMe controller for reboot/poweroff without
    /// unregistering userspace-visible block publication.
    /// # C: O(N_nvme + controller shutdown)
    pub fn shutdown(device_key: pci::Bdf) -> bool {
        let dev = match DEVICES
            .lock_bh::<NvmeBh>()
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

    /// Reset one published controller without changing its disk identity.
    /// # C: O(N_nvme + controller reset)
    pub fn reset(device_key: pci::Bdf) -> bool {
        let record = DEVICES.lock_bh::<NvmeBh>()
            .iter()
            .find(|record| record.device_key == device_key)
            .map(|record| (record.name.clone(), record.nsid, record.dev.clone()));
        let Some((name, nsid, dev)) = record else { return false; };
        reset::live(&name, nsid, &dev)
    }

    /// Original PCI command bits saved before this driver enabled decode.
    /// # C: O(N_nvme)
    pub fn command_orig_for(device_key: pci::Bdf) -> Option<u16> {
        DEVICES
            .lock_bh::<NvmeBh>()
            .iter()
            .find(|rec| rec.device_key == device_key)
            .map(|rec| rec.command_orig)
    }
}

#[cfg(target_os = "oxide-kernel")]
pub use imp::{command_orig_for, device_key_from_bdf, init, remove, reset, shutdown, NvmeBlk, NVME_CLASS24};

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

/// The D1a model driver for NVMe: matches PCI class 0x010802 on the PCI bus.
/// Registered + bound at the bring-up success site in pci-boot.
#[cfg(target_os = "oxide-kernel")]
pub struct NvmeDriver;

#[cfg(target_os = "oxide-kernel")]
impl drv::Driver for NvmeDriver {
    fn name(&self) -> &'static str { "nvme" }
    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "pci" && dev.class == imp::NVME_CLASS24
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
        let Some(resource) = dev.resources.iter().find(|resource| resource.bar == 0 && resource.flags & drv::IORESOURCE_MEM != 0) else {
            restore_pci_bus_master(dev, command_orig);
            return Err(drv::Error::ProbeFailed);
        };
        let bar0_pa = resource.start;
        let bar_bytes = resource.end.checked_sub(resource.start).and_then(|bytes| bytes.checked_add(1)).ok_or(drv::Error::ProbeFailed)?;
        let map_bytes = (bar0_pa & BAR_PAGE_OFFSET_MASK).checked_add(bar_bytes).ok_or(drv::Error::ProbeFailed)?;
        let pages = map_bytes.checked_add(BAR_PAGE_OFFSET_MASK).and_then(|bytes| bytes.checked_div(BAR_PAGE_SIZE)).ok_or(drv::Error::ProbeFailed)?;
        // SAFETY: BAR0 was enumerated for this NVMe function; this mapping owns its complete page-rounded aperture.
        let mmio = unsafe { mmio_map::map_owned(bar0_pa & BAR_PAGE_BASE_MASK, pages) };
        let device_key = imp::device_key_from_bdf(bdf);
        if imp::init(device_key, command_orig, dev.vendor_id, dev.device_id, mmio, bar0_pa & BAR_PAGE_OFFSET_MASK) == 0 {
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
pub static NVME_DRIVER: NvmeDriver = NvmeDriver;
