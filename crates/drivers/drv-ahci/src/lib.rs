// AHCI/SATA block driver (drivers-plan D3.6). A real HBA bring-up: GHC.AE →
// scan Ports Implemented → first port with a SATA disk (DET==3, SIG==0x101)
// → stop/program/start the port → ATA IDENTIFY → READ/WRITE DMA EXT via a
// PRDT bounce frame, exposed as a `block::BlockDevice` under the registry
// name `sata0`. The model driver's `probe` matches PCI class 0x010601 (QEMU
// ich9-ahci vendor 0x8086 device 0x2922), maps BAR5 (ABAR), and calls `init`.
//
// Layering: `regs.rs` = pure register/FIS/IDENTIFY math (host-tested);
// `port.rs` = the kernel-only MMIO + command mechanics (the `Ahci`
// controller); this file = the BlockDevice impl + registration + PCI
// bring-up glue. Mirrors drv-nvme: one synchronous in-flight request,
// serialised by a Spinlock; per-chunk loop over a one-page bounce frame.

#![no_std]

extern crate alloc;

mod regs;
#[cfg(target_os = "oxide-kernel")]
mod port;

#[cfg(target_os = "oxide-kernel")]
mod imp {
    use crate::pci::Bdf;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use sync::{Spinlock, TaskList as DriverLockClass};
    use block::{BlockDevice, BlockRequest, BlockError, BlockOp, KResult};
    use crate::port::Ahci;

    /// PCI class for an AHCI controller: base 0x01 (mass storage), subclass
    /// 0x06 (SATA), prog-if 0x01 (AHCI 1.0). # C: O(1)
    pub const AHCI_CLASS24: u32 = 0x01_06_01;

    /// The registered `BlockDevice`: an `Ahci` controller behind a Spinlock
    /// (one command slot, one in-flight command — the lock serialises every
    /// submit, mirroring drv-nvme's NvmeBlk).
    pub struct AhciBlk {
        ctrl:     Spinlock<Ahci, DriverLockClass>,
        blk_size: u32,
        capacity: u64,
        removed:  AtomicBool,
    }

    impl AhciBlk {
        /// Bytes the PRDT bounce frame can carry per transfer (one page). # C: O(1)
        fn chunk_bytes(&self) -> usize { Ahci::MAX_XFER as usize }

        /// Blocks per chunk (bounce frame size / block size). # C: O(1)
        fn chunk_blocks(&self) -> u64 {
            (self.chunk_bytes() as u64) / (self.blk_size as u64)
        }
    }

    impl BlockDevice for AhciBlk {
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
                        let lba = req.start_block + done;
                        let mut c = self.ctrl.lock();
                        let bva = c.bounce_va();
                        if bva == 0 { return Err(BlockError::Eio); }
                        let p = bva as *mut u8;
                        if write {
                            // Stage payload into the PRDT bounce frame.
                            // SAFETY: HHDM-mapped bounce frame the controller
                            // owns for this in-flight cmd (held under the ctrl
                            // lock); `len` ≤ one page (cblk bounds it); aligned
                            // byte stores stay within the frame.
                            unsafe {
                                for i in 0..len {
                                    core::ptr::write_volatile(p.add(i), req.buffer[off + i]);
                                }
                            }
                        }
                        let ok = c.rw(write, lba, n as u16);
                        if !ok { return Err(BlockError::Eio); }
                        if !write {
                            // Copy device-written data out of the bounce frame.
                            // SAFETY: same HHDM-mapped bounce frame, now filled
                            // by the controller; aligned byte loads within `len`
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

    impl AhciBlk {
        /// Remove publication before calling this, then quiesce hardware and
        /// release AHCI DMA frames. Existing Arc holders observe EIO.
        /// # C: O(port stop + PMM frees)
        fn remove(&self) {
            self.removed.store(true, Ordering::Release);
            self.ctrl.lock().shutdown_and_free();
        }
    }

    struct Installed {
        dev: Arc<AhciBlk>,
        bdf: Bdf,
        cmd_orig: u16,
    }

    static INSTALLED: Spinlock<Option<Installed>, DriverLockClass> = Spinlock::new(None);

    /// Bring up the AHCI controller whose ABAR (BAR5) register file is mapped
    /// by `mmio` (≥2 pages), register the first SATA
    /// disk as `sata0`, and return the 1-based registry index (0 on failure).
    /// Optionally self-tests by reading LBA 0. # C: O(bring-up) + registry O(N)
    pub fn init(mmio: mmio_map::Mapping, abar_off: u64, bdf: Bdf, cmd_orig: u16) -> u32 {
        let a = match Ahci::bring_up(mmio, abar_off) { Ok(a) => a, Err(reason) => {
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

        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  ahci: port0 ready sectors=");
            klog::write_dec_u64(capacity);
            klog::write_raw(b" bsz=");
            klog::write_dec_u64(blk_size as u64);
            klog::write_raw(b"\n");
        }

        let dev = Arc::new(AhciBlk {
            ctrl: Spinlock::new(a),
            blk_size, capacity,
            removed: AtomicBool::new(false),
        });

        // Optional bring-up self-test: read LBA 0 (proves the command-issue +
        // PRDT path end-to-end). Logged; a failure does not block register.
        #[cfg(feature = "debug-boot")]
        {
            let mut req = BlockRequest::new_read(0, 1, blk_size);
            let ok = dev.submit_sync(&mut req).is_ok();
            klog::write_raw(b"[INFO]  ahci: lba0 read selftest=");
            klog::write_dec_u64(ok as u64);
            klog::write_raw(b"\n");
        }

        let block_dev: Arc<dyn BlockDevice> = dev.clone();
        let idx = block::registry::register_with_serial("sata0", Some("oxsata"), block_dev);
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
            klog::write_raw(b"[INFO]  ahci: block dev registered idx=");
            klog::write_dec_u64(idx as u64);
            klog::write_raw(b"\n");
        }
        idx
    }

    /// Remove the registered AHCI disk and release controller-owned resources.
    /// # C: O(N_disks + port shutdown)
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
        let _ = block::registry::unregister("sata0");
        current.dev.remove();
        crate::restore_command(current.bdf, current.cmd_orig);
        true
    }
}

#[cfg(target_os = "oxide-kernel")]
pub use imp::{init, remove, AhciBlk, AHCI_CLASS24};

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
        let cmd_orig = enable_and_capture_command(bdf).ok_or(drv::Error::ProbeFailed)?;
        let bars = decode_bars(bdf);
        let abar_pa = bars[5].mem_base().unwrap_or(0);
        if abar_pa == 0 {
            restore_command(bdf, cmd_orig);
            return Err(drv::Error::ProbeFailed);
        }
        // SAFETY: BAR5 PA came from this PCI function's config space; two
        // pages cover generic HBA registers plus the 32-port register array.
        let mmio = unsafe { mmio_map::map_owned(abar_pa & !0xFFF, 2) };
        if imp::init(mmio, abar_pa & 0xFFF, bdf, cmd_orig) == 0 {
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
pub static AHCI_DRIVER: AhciDriver = AhciDriver;
