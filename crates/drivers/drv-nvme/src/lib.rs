// NVMe block driver (drivers-plan D3.5). A real controller bring-up: reset →
// admin SQ/CQ → IDENTIFY controller + namespace 1 → one I/O queue pair →
// READ/WRITE via a PRP bounce frame, exposed as a `block::BlockDevice` under
// Linux-style registry names `nvme0n1`, `nvme1n1`, ... . The model driver's
// `probe` matches PCI class
// 0x010802 (QEMU vendor 0x1b36 device 0x0010), maps BAR0, and calls `init`.
//
// Layering: `regs.rs` = pure register/bit math (host-tested); `queue.rs` =
// the kernel-only MMIO + queue mechanics (the `Nvme` controller);
// `lifecycle.rs` = hosted cleanup-order proof; this file =
// the BlockDevice impl + registration + PCI bring-up glue. Mirrors
// drv-virtio-blk: one synchronous in-flight request, serialised by a Spinlock.

#![no_std]

extern crate alloc;

mod regs;
#[cfg(any(target_os = "oxide-kernel", test))]
mod lifecycle;
#[cfg(target_os = "oxide-kernel")]
mod queue;

#[cfg(target_os = "oxide-kernel")]
mod imp {
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use sync::{Spinlock, TaskList as DriverLockClass};
    use block::{BlockDevice, BlockRequest, BlockError, BlockOp, KResult};
    use crate::queue::Nvme;

    /// PCI class for an NVMe controller: base 0x01 (mass storage), subclass
    /// 0x08 (non-volatile memory), prog-if 0x02 (NVMe). # C: O(1)
    pub const NVME_CLASS24: u32 = 0x01_08_02;

    /// The registered `BlockDevice`: an `Nvme` controller behind a Spinlock
    /// (single I/O queue, one in-flight command — the lock serialises every
    /// submit, mirroring drv-virtio-rng's whole-body lock).
    pub struct NvmeBlk {
        ctrl:     Spinlock<Nvme, DriverLockClass>,
        blk_size: u32,
        capacity: u64,
        removed:  AtomicBool,
    }

    impl NvmeBlk {
        /// Bytes the PRP bounce frame can carry per transfer (one page). # C: O(1)
        fn chunk_bytes(&self) -> usize { Nvme::MAX_XFER as usize }

        /// Blocks per chunk (PRP bounce frame size / block size). # C: O(1)
        fn chunk_blocks(&self) -> u64 {
            (self.chunk_bytes() as u64) / (self.blk_size as u64)
        }
    }

    impl BlockDevice for NvmeBlk {
        fn block_size(&self) -> u32 { self.blk_size }
        fn capacity_blocks(&self) -> u64 { self.capacity }

        fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
            if self.removed.load(Ordering::Acquire) {
                return Err(BlockError::Eio);
            }
            let bs = self.blk_size as usize;
            match req.op {
                BlockOp::Flush => {
                    let mut c = self.ctrl.lock();
                    if self.removed.load(Ordering::Acquire) {
                        return Err(BlockError::Eio);
                    }
                    if c.flush() { Ok(()) } else { Err(BlockError::Eio) }
                }
                BlockOp::Discard | BlockOp::WriteZeroes { .. } => Err(BlockError::Eopnotsupp),
                BlockOp::Read | BlockOp::Write => {
                    let nbytes = (req.len_blocks as usize)
                        .checked_mul(bs).ok_or(BlockError::Einval)?;
                    if req.op == BlockOp::Read {
                        if req.buffer.len() < nbytes { req.buffer.resize(nbytes, 0); }
                    } else if req.buffer.len() < nbytes {
                        return Err(BlockError::Einval);
                    }
                    let write = req.op == BlockOp::Write;
                    let cblk = self.chunk_blocks().max(1);
                    let mut done: u64 = 0;
                    let total = req.len_blocks as u64;
                    while done < total {
                        let n = core::cmp::min(cblk, total - done);
                        let off = (done as usize) * bs;
                        let len = (n as usize) * bs;
                        let slba = req.start_block + done;
                        let mut c = self.ctrl.lock();
                        if self.removed.load(Ordering::Acquire) {
                            return Err(BlockError::Eio);
                        }
                        let pva = c.prp_va();
                        if pva == 0 { return Err(BlockError::Eio); }
                        let p = pva as *mut u8;
                        if write {
                            // Stage payload into the PRP bounce frame.
                            // SAFETY: HHDM-mapped PRP frame the controller
                            // owns for this in-flight cmd (held under the
                            // ctrl lock); `len` ≤ one page (cblk bounds it);
                            // aligned byte stores stay within the frame.
                            unsafe {
                                for i in 0..len {
                                    core::ptr::write_volatile(p.add(i), req.buffer[off + i]);
                                }
                            }
                        }
                        let ok = c.rw(write, slba, (n - 1) as u16);
                        if !ok { return Err(BlockError::Eio); }
                        if !write {
                            // Copy device-written data out of the bounce frame.
                            // SAFETY: same HHDM-mapped PRP frame, now filled by
                            // the controller; aligned byte loads within `len`
                            // ≤ one page; still under the ctrl lock.
                            unsafe {
                                for i in 0..len {
                                    req.buffer[off + i] = core::ptr::read_volatile(p.add(i));
                                }
                            }
                        }
                        drop(c);
                        done += n;
                    }
                    Ok(())
                }
            }
        }

        fn flush(&self) -> KResult<()> {
            if self.removed.load(Ordering::Acquire) {
                return Err(BlockError::Eio);
            }
            let mut c = self.ctrl.lock();
            if self.removed.load(Ordering::Acquire) {
                return Err(BlockError::Eio);
            }
            if c.flush() { Ok(()) } else { Err(BlockError::Eio) }
        }
    }

    impl NvmeBlk {
        /// Remove publication before calling this, then quiesce hardware and
        /// release queue/PRP frames. Existing Arc holders observe EIO.
        /// # C: O(controller shutdown + PMM frees)
        fn remove(&self) {
            self.removed.store(true, Ordering::Release);
            self.ctrl.lock().shutdown_and_free();
        }

        /// Quiesce for reboot/poweroff without unregistering the block device.
        /// Existing Arc holders observe EIO while userspace publication stays
        /// intact for the terminal power transition.
        /// # C: O(controller shutdown + PMM frees)
        fn shutdown(&self) {
            self.removed.store(true, Ordering::Release);
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
        dev:        Arc<NvmeBlk>,
    }

    static DEVICES: Spinlock<Vec<NvmeRecord>, DriverLockClass> = Spinlock::new(Vec::new());

    #[cfg(feature = "debug-boot")]
    fn key_bus(key: pci::Bdf) -> u8 { key.bus }
    #[cfg(feature = "debug-boot")]
    fn key_device(key: pci::Bdf) -> u8 { key.device }
    #[cfg(feature = "debug-boot")]
    fn key_function(key: pci::Bdf) -> u8 { key.function }

    fn nvme_name(index: u32) -> String {
        alloc::format!("nvme{}n1", index)
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
        mmio: mmio_map::Mapping,
        bar0_off: u64,
    ) -> u32 {
        if DEVICES.lock().iter().any(|rec| rec.device_key == device_key) {
            return 0;
        }
        let nv = match Nvme::bring_up(mmio, bar0_off) { Some(n) => n, None => {
            #[cfg(feature = "debug-boot")]
            { klog::write_raw(b"[WARN]  nvme: controller bring-up failed\n"); }
            return 0;
        }};
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
            blk_size, capacity,
            removed: AtomicBool::new(false),
        });

        // Optional bring-up self-test: read LBA 0 (proves the I/O queue +
        // PRP path end-to-end). Logged; a failure does not block register.
        #[cfg(feature = "debug-boot")]
        {
            let mut req = BlockRequest::new_read(0, 1, blk_size);
            let ok = dev.submit_sync(&mut req).is_ok();
            klog::write_raw(b"[INFO]  nvme: lba0 read selftest=");
            klog::write_dec_u64(ok as u64);
            klog::write_raw(b"\n");
        }

        let name = nvme_name(NEXT_DISK_INDEX.fetch_add(1, Ordering::Relaxed));
        let existed = block::registry::by_name(&name).is_some();
        let idx = block::registry::register_with_driver(
            block::registry::BlockDriver::fixed("nvme", block::uapi::NVME_BLK_MAJOR), &name,
            Some("oxnvme"),
            dev.clone() as Arc<dyn BlockDevice>,
        );
        let published = if idx != 0 && !existed {
            let mut devices = DEVICES.lock();
            if devices.iter().any(|rec| rec.device_key == device_key) {
                false
            } else {
                devices.push(NvmeRecord {
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
            return 0;
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
            let mut devices = DEVICES.lock();
            match devices.iter().position(|rec| rec.device_key == device_key) {
                Some(i) => devices.remove(i),
                None => return false,
            }
        };
        let _ = block::registry::unregister(&rec.name);
        rec.dev.remove();
        true
    }

    /// Quiesce the bound NVMe controller for reboot/poweroff without
    /// unregistering userspace-visible block publication.
    /// # C: O(N_nvme + controller shutdown)
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
    /// # C: O(N_nvme)
    pub fn command_orig_for(device_key: pci::Bdf) -> Option<u16> {
        DEVICES
            .lock()
            .iter()
            .find(|rec| rec.device_key == device_key)
            .map(|rec| rec.command_orig)
    }
}

#[cfg(target_os = "oxide-kernel")]
pub use imp::{command_orig_for, device_key_from_bdf, init, remove, shutdown, NvmeBlk, NVME_CLASS24};

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
        let bars = decode_bars(bdf);
        let bar0_pa = bars[0].mem_base().unwrap_or(0);
        if bar0_pa == 0 {
            restore_pci_bus_master(dev, command_orig);
            return Err(drv::Error::ProbeFailed);
        }
        // SAFETY: BAR0 PA came from this PCI function's config space; two
        // pages cover the controller register file and QEMU doorbells.
        let mmio = unsafe { mmio_map::map_owned(bar0_pa & BAR_PAGE_BASE_MASK, 2) };
        let device_key = imp::device_key_from_bdf(bdf);
        if imp::init(device_key, command_orig, mmio, bar0_pa & BAR_PAGE_OFFSET_MASK) == 0 {
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
