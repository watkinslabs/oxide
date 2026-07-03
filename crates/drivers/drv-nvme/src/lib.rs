// NVMe block driver (drivers-plan D3.5). A real controller bring-up: reset →
// admin SQ/CQ → IDENTIFY controller + namespace 1 → one I/O queue pair →
// READ/WRITE via a PRP bounce frame, exposed as a `block::BlockDevice` under
// the registry name `nvme0n1`. The model driver's `probe` matches PCI class
// 0x010802 (QEMU vendor 0x1b36 device 0x0010), maps BAR0, and calls `init`.
//
// Layering: `regs.rs` = pure register/bit math (host-tested); `queue.rs` =
// the kernel-only MMIO + queue mechanics (the `Nvme` controller); this file =
// the BlockDevice impl + registration + PCI bring-up glue. Mirrors
// drv-virtio-blk: one synchronous in-flight request, serialised by a Spinlock.

#![no_std]

extern crate alloc;

mod regs;
#[cfg(target_os = "oxide-kernel")]
mod queue;

#[cfg(target_os = "oxide-kernel")]
mod imp {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use sync::{Spinlock, TaskList as DriverLockClass};
    use block::{BlockDevice, BlockRequest, BlockError, BlockOp, KResult};
    use crate::queue::Nvme;
    use crate::pci::Bdf;

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
                    if c.flush() { Ok(()) } else { Err(BlockError::Eio) }
                }
                BlockOp::Discard => Err(BlockError::Eopnotsupp),
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
    }

    struct Installed {
        dev: Arc<NvmeBlk>,
        bdf: Bdf,
        cmd_orig: u16,
    }

    static INSTALLED: Spinlock<Option<Installed>, DriverLockClass> = Spinlock::new(None);

    /// Bring up the NVMe controller mapped by `mmio` (BAR0 register file,
    /// ≥2 pages), register it as `nvme0n1`, and return the
    /// 1-based registry index (0 on failure). Optionally self-tests by reading
    /// LBA 0. # C: O(controller bring-up) + registry O(N_disks)
    pub fn init(mmio: mmio_map::Mapping, bar0_off: u64, bdf: Bdf, cmd_orig: u16) -> u32 {
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

        let idx = block::registry::register_with_serial(
            "nvme0n1",
            Some("oxnvme"),
            dev.clone() as Arc<dyn BlockDevice>,
        );
        if idx == 0 {
            dev.remove();
            return 0;
        }
        *INSTALLED.lock() = Some(Installed {
            dev,
            bdf,
            cmd_orig,
        });
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  nvme: block dev registered idx=");
            klog::write_dec_u64(idx as u64);
            klog::write_raw(b"\n");
        }
        idx
    }

    /// Remove the registered NVMe disk and release controller-owned resources.
    /// # C: O(N_disks + controller shutdown)
    pub fn remove(bdf: Bdf) -> bool {
        let mut installed = INSTALLED.lock();
        let mut current = match installed.take() {
            Some(state) => state,
            None => return false,
        };
        if current.bdf != bdf {
            *installed = Some(current);
            return false;
        }
        let _ = block::registry::unregister("nvme0n1");
        current.dev.remove();
        crate::restore_command(current.bdf, current.cmd_orig);
        true
    }
}

#[cfg(target_os = "oxide-kernel")]
pub use imp::{init, remove, NvmeBlk, NVME_CLASS24};

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn decode_bars(bdf: pci::Bdf) -> [pci::Bar; 6] {
    let r = hal_x86_64::pci::LegacyPci;
    pci::decode_bars(&r, bdf)
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn decode_bars(bdf: pci::Bdf) -> [pci::Bar; 6] {
    match hal_aarch64::pci::EcamPci::from_published() {
        Some(r) => pci::decode_bars(&r, bdf),
        None => [pci::Bar::None; 6],
    }
}

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
        let cmd_orig = enable_and_capture_command(bdf).ok_or(drv::Error::ProbeFailed)?;
        let bars = decode_bars(bdf);
        let bar0_pa = bars[0].mem_base().unwrap_or(0);
        if bar0_pa == 0 {
            restore_command(bdf, cmd_orig);
            return Err(drv::Error::ProbeFailed);
        }
        // SAFETY: BAR0 PA came from this PCI function's config space; two
        // pages cover the controller register file and QEMU doorbells.
        let mmio = unsafe { mmio_map::map_owned(bar0_pa & !0xFFF, 2) };
        if imp::init(mmio, bar0_pa & 0xFFF, bdf, cmd_orig) == 0 {
            restore_command(bdf, cmd_orig);
            return Err(drv::Error::ProbeFailed);
        }
        Ok(())
    }

    fn remove(&self, dev: &drv::Device) {
        let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else {
            return;
        };
        let _ = imp::remove(bdf);
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn enable_and_capture_command(bdf: pci::Bdf) -> Option<u16> {
    let r = hal_x86_64::pci::LegacyPci;
    Some(pci::enable_mem_bus_master(&r, bdf))
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn restore_command(bdf: pci::Bdf, command: u16) {
    let r = hal_x86_64::pci::LegacyPci;
    pci::write_command(&r, bdf, command);
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn enable_and_capture_command(bdf: pci::Bdf) -> Option<u16> {
    let r = hal_aarch64::pci::EcamPci::from_published()?;
    Some(pci::enable_mem_bus_master(&r, bdf))
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn restore_command(bdf: pci::Bdf, command: u16) {
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
        pci::write_command(&r, bdf, command);
    }
}

/// Singleton driver instance for registration. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub static NVME_DRIVER: NvmeDriver = NvmeDriver;
