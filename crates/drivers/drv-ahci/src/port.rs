// AHCI HBA + port bring-up + command-issue mechanics (kernel-only — pure
// MMIO + HHDM, so this file is `cfg(target_os = "oxide-kernel")`; the math it
// uses lives in `regs.rs` and host-tests). Mirrors drv-nvme/src/queue: the
// boot probe maps ABAR (BAR5) and hands the register-file VA here; this module
// owns GHC.AE → per-port reset → IDENTIFY → READ/WRITE DMA EXT.
//
// One implemented SATA-disk port, command slot 0 only, one in-flight command
// at a time, serialised by the caller's Spinlock (see lib.rs). Completion is
// polled on PxCI bit 0 clearing.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

use crate::regs;
use mmio_map::Mapping;

/// HHDM base for the running arch (PA→VA for HBA DMA structures + bounce).
/// # C: O(1)
#[inline]
fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// Monotonic wall-clock ns (0 if unsupported) — bounds the busy/completion
/// polls by real time rather than a CPU-speed-dependent spin count. # C: O(1)
#[inline]
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// 4 KiB host page size; one PMM frame.
const PAGE: u64 = 0x1000;

/// Worst-case wait for a command completion or a port stop. 5 s is generous
/// for QEMU's emulated AHCI; bounds a genuinely-lost completion to EIO.
const IO_TIMEOUT_NS: u64 = 5_000_000_000;
/// Per-port SATA PHY link-up timeout after COMRESET (bounded so empty ports
/// don't stall boot; a real link establishes in well under this).
const LINK_TIMEOUT_NS: u64 = 200_000_000;

/// Command-FIS length in dwords for an H2D Register FIS (20 bytes = 5 dwords).
const CFL_DWORDS: u32 = 5;

/// Offset of the PRDT within the command table (after the 0x80-byte CFIS +
/// ATAPI + reserved region, AHCI §4.2.3).
const CT_PRDT_OFF: usize = 0x80;

/// The AHCI controller bring-up state for one SATA-disk port. Holds the ABAR
/// register-file VA, the port index, the DMA-structure PAs (command list,
/// received-FIS, command table, bounce frame), and the negotiated geometry.
pub struct Ahci {
    mmio:      Mapping,
    abar_va: u64,
    port:    u32,
    clb_pa:  u64,  // command list (1 KiB, 1 KiB-aligned)
    fb_pa:   u64,  // received FIS (256 B, 256 B-aligned)
    ctba_pa: u64,  // command table for slot 0 (128 B header + PRDT)
    /// Bounce frame (one 4 KiB page) — the data buffer for one I/O.
    bounce_pa: u64,
    /// Disk geometry harvested at IDENTIFY.
    pub sectors:   u64,
    pub blk_size:  u32,
    /// ATA IDENTIFY DEVICE serial, if the device reports a non-padding value.
    pub serial:    Option<String>,
}

// SAFETY justification: Ahci holds raw PAs/VAs into HHDM/MMIO stable for the
// device's lifetime; all mutable port access is serialised by the Spinlock
// the owner (lib.rs AhciBlk) wraps it in, so cross-CPU sharing is sound — no
// interior mutation escapes that lock.
unsafe impl Send for Ahci {}
unsafe impl Sync for Ahci {}

impl Ahci {
    fn free_frame(pa: &mut u64) {
        if *pa == 0 {
            return;
        }
        // SAFETY: the caller has stopped/quiesced the port. These frames are
        // the single-page AHCI command/FIS/table/bounce allocations returned
        // by alloc_one_frame during bring-up.
        unsafe { pmm::setup::free_one_frame(*pa); }
        *pa = 0;
    }

    fn alloc_frames() -> Result<[u64; 4], &'static str> {
        let mut frames = [0u64; 4];
        let names = ["alloc clb", "alloc fb", "alloc ct", "alloc bounce"];
        let mut i = 0usize;
        while i < frames.len() {
            match pmm::setup::alloc_one_frame() {
                Some(pa) => frames[i] = pa,
                None => {
                    for pa in frames.iter_mut() {
                        Self::free_frame(pa);
                    }
                    return Err(names[i]);
                }
            }
            i += 1;
        }
        Ok(frames)
    }

    /// Stop the active port and return command/FIS/table/bounce frames to PMM.
    /// Publication must already be removed, or the system must be in terminal
    /// shutdown, and callers quiesced.
    /// # C: O(port stop wait + 4 frees)
    pub fn shutdown_and_free(&mut self) {
        if self.abar_va != 0 {
            let _ = self.stop_port();
            self.pw(regs::P_CLB, 0);
            self.pw(regs::P_CLBU, 0);
            self.pw(regs::P_FB, 0);
            self.pw(regs::P_FBU, 0);
        }
        Self::free_frame(&mut self.clb_pa);
        Self::free_frame(&mut self.fb_pa);
        Self::free_frame(&mut self.ctba_pa);
        Self::free_frame(&mut self.bounce_pa);
        self.abar_va = 0;
        self.mmio.unmap();
    }

    /// Bytes one transfer carries (one bounce frame = one page). # C: O(1)
    pub const MAX_XFER: u64 = PAGE;

    /// Read a 32-bit HBA/port register at ABAR + `off`. # C: O(1)
    #[inline]
    fn r32(&self, off: u64) -> u32 {
        // SAFETY: abar_va is the Device-attr-mapped AHCI register file
        // (map_mmio_pages, 2 pages); `off` is a spec HBA/port register offset
        // within the mapped window; aligned 32-bit MMIO load.
        unsafe { core::ptr::read_volatile((self.abar_va + off) as *const u32) }
    }
    /// Write a 32-bit HBA/port register at ABAR + `off`. # C: O(1)
    #[inline]
    fn w32(&self, off: u64, val: u32) {
        // SAFETY: abar_va is the Device-attr-mapped AHCI register file; `off`
        // is a spec HBA/port register offset within the mapped window; aligned
        // 32-bit MMIO store to a register the driver exclusively owns.
        unsafe { core::ptr::write_volatile((self.abar_va + off) as *mut u32, val); }
    }
    /// Read a 32-bit per-port register of this port. # C: O(1)
    #[inline]
    fn pr(&self, reg: u64) -> u32 { self.r32(regs::port_reg(self.port, reg)) }
    /// Write a 32-bit per-port register of this port. # C: O(1)
    #[inline]
    fn pw(&self, reg: u64, val: u32) { self.w32(regs::port_reg(self.port, reg), val); }

    /// Zero a freshly-PMM-allocated frame via HHDM. # C: O(page)
    fn zero_frame(pa: u64) {
        let h = hhdm();
        if h == 0 || pa == 0 { return; }
        let va = h.wrapping_add(pa) as *mut u8;
        // SAFETY: HHDM-mapped freshly-PMM-allocated frame we exclusively own;
        // aligned byte stores span exactly one 4 KiB page (never past the
        // frame the buddy returned), giving deterministic initial state.
        unsafe { for i in 0..(PAGE as usize) { core::ptr::write_volatile(va.add(i), 0); } }
    }

    /// Bring up the HBA + the first implemented SATA-disk port, run IDENTIFY,
    /// and return the ready controller. `Err(reason)` on no disk (a benign
    /// empty HBA, reason starts "no ") or a real failure (timeout/alloc).
    /// `abar_va` is the BAR5 register-file VA (≥2 pages from map_mmio_pages).
    /// # C: O(reset + port init + 1 IDENTIFY)
    pub fn bring_up(mmio: Mapping, abar_off: u64) -> Result<Ahci, &'static str> {
        let abar_va = mmio.base_va() + abar_off;
        // Enable AHCI mode (GHC.AE) before touching port registers.
        // SAFETY: abar_va is the Device-attr-mapped HBA register file; aligned
        // 32-bit RMW of GHC to set the AE bit per AHCI §10.1.1.
        let ghc = unsafe { core::ptr::read_volatile((abar_va + regs::HBA_GHC) as *const u32) };
        // SAFETY: same Device-attr HBA register file; setting GHC.AE switches
        // the HBA out of legacy IDE compatibility into AHCI register access.
        unsafe { core::ptr::write_volatile((abar_va + regs::HBA_GHC) as *mut u32, ghc | regs::GHC_AE); }

        // Ports Implemented bitmap (AHCI §3.1.6).
        // SAFETY: Device-attr HBA register file; aligned 32-bit load of PI.
        let pi = unsafe { core::ptr::read_volatile((abar_va + regs::HBA_PI) as *const u32) };
        if pi == 0 { return Err("no ports implemented"); }

        // Find the first implemented port that has a SATA disk attached.
        // The SATA PHY link (PxSSTS.DET) is not necessarily established just by
        // enabling AHCI: on some hosts (notably the aarch64 virt machine) the
        // port presents no link until the guest drives a COMRESET. So for each
        // implemented port issue a COMRESET (PxSCTL.DET=1, hold ≥1ms, DET=0)
        // then wait for the PHY link (PxSSTS.DET==3) — the Linux libata reset
        // sequence (AHCI §10.1.2 / SATA §). Bounded so an empty port can't
        // stall boot.
        let mut chosen: Option<u32> = None;
        for n in 0..32u32 {
            if pi & (1 << n) == 0 { continue; }
            let sctl_off = regs::port_reg(n, regs::P_SCTL);
            let ssts_off = regs::port_reg(n, regs::P_SSTS);
            // SAFETY: Device-attr HBA register file; per-port PxSCTL within the
            // mapped window; aligned 32-bit RMW to drive DET=1 (COMRESET init).
            unsafe {
                let s = core::ptr::read_volatile((abar_va + sctl_off) as *const u32);
                core::ptr::write_volatile((abar_va + sctl_off) as *mut u32, (s & !0xF) | 0x1);
            }
            let hold = now_ns().saturating_add(2_000_000); // ≥1ms COMRESET hold
            while now_ns() < hold { core::hint::spin_loop(); }
            // SAFETY: same per-port PxSCTL; clear DET back to 0 to resume the
            // link after the COMRESET hold window.
            unsafe {
                let s = core::ptr::read_volatile((abar_va + sctl_off) as *const u32);
                core::ptr::write_volatile((abar_va + sctl_off) as *mut u32, s & !0xF);
            }
            let deadline = now_ns().saturating_add(LINK_TIMEOUT_NS);
            let mut ssts;
            loop {
                // SAFETY: Device-attr HBA register file; per-port PxSSTS within
                // the mapped window; aligned 32-bit load of the SATA status.
                ssts = unsafe { core::ptr::read_volatile((abar_va + ssts_off) as *const u32) };
                if ssts & regs::SSTS_DET_MASK == regs::SSTS_DET_READY { break; }
                if now_ns() >= deadline { break; }
                core::hint::spin_loop();
            }
            if ssts & regs::SSTS_DET_MASK != regs::SSTS_DET_READY { continue; }
            // Device present + PHY up. Do NOT gate on PxSIG here: the signature
            // register is only populated from the device's first D2H register
            // FIS, which arrives after FRE is enabled (in start_port below) —
            // x86 QEMU pre-populates it, aarch64 virt does not. Select on the
            // live link and let IDENTIFY confirm it's an ATA disk (libata does
            // the same: link first, classify after the reset/FIS).
            chosen = Some(n);
            break;
        }
        let port = chosen.ok_or("no SATA disk")?;

        // Allocate the per-port DMA structures + a bounce frame (each its own
        // PMM frame — over-aligned for the 1 KiB / 256 B requirements).
        let [clb, fb, ct, bnc] = Self::alloc_frames()?;
        for f in [clb, fb, ct, bnc] { Self::zero_frame(f); }

        let mut a = Ahci {
            mmio, abar_va, port,
            clb_pa: clb, fb_pa: fb, ctba_pa: ct, bounce_pa: bnc,
            sectors: 0, blk_size: 512, serial: None,
        };

        // Stop the port, program the bases, restart it.
        if !a.stop_port() {
            a.shutdown_and_free();
            return Err("stop_port timeout");
        }
        a.pw(regs::P_CLB,  (a.clb_pa & 0xFFFF_FFFF) as u32);
        a.pw(regs::P_CLBU, (a.clb_pa >> 32) as u32);
        a.pw(regs::P_FB,   (a.fb_pa & 0xFFFF_FFFF) as u32);
        a.pw(regs::P_FBU,  (a.fb_pa >> 32) as u32);
        // Clear any latched SATA error + interrupt status before start.
        a.pw(regs::P_SERR, 0xFFFF_FFFF);
        a.pw(regs::P_IS,   0xFFFF_FFFF);
        if !a.start_port() {
            a.shutdown_and_free();
            return Err("start_port timeout");
        }

        // PxSIG is valid now that FRE received the device's D2H FIS. Classify:
        // only an ATA SATA disk (0x00000101) is a block device we drive — an
        // empty port / non-disk signature is a benign "no disk", not a failure.
        if a.pr(regs::P_SIG) != regs::SIG_SATA_DISK {
            a.shutdown_and_free();
            return Err("no SATA disk");
        }

        // IDENTIFY DEVICE → geometry.
        if !a.identify() {
            a.shutdown_and_free();
            return Err("identify failed");
        }
        Ok(a)
    }

    /// Stop the port: clear ST + FRE, wait for CR + FR to clear (AHCI §10.3.2).
    /// # C: O(poll until CR+FR clear)
    fn stop_port(&self) -> bool {
        let mut cmd = self.pr(regs::P_CMD);
        cmd &= !regs::CMD_ST;
        cmd &= !regs::CMD_FRE;
        self.pw(regs::P_CMD, cmd);
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        loop {
            let c = self.pr(regs::P_CMD);
            if c & (regs::CMD_CR | regs::CMD_FR) == 0 { return true; }
            if now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Start the port: enable FRE FIRST, then wait for the device to settle
    /// (not BSY/DRQ), then set ST (AHCI §10.3.1). FRE must precede the wait:
    /// the device clears BSY only once its initial D2H register FIS is received,
    /// which requires FIS-receive enabled — on aarch64 virt the device is still
    /// BSY post-COMRESET until then (x86 QEMU pre-clears). # C: O(poll until idle)
    fn start_port(&self) -> bool {
        // FRE on so the device's D2H FIS lands (clears BSY + populates PxSIG).
        let mut cmd = self.pr(regs::P_CMD);
        cmd |= regs::CMD_FRE;
        self.pw(regs::P_CMD, cmd);
        // Now wait for the device to settle (not BSY, not DRQ).
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        loop {
            let tfd = self.pr(regs::P_TFD);
            if tfd & (regs::TFD_BSY | regs::TFD_DRQ) == 0 { break; }
            if now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
        cmd = self.pr(regs::P_CMD);
        cmd |= regs::CMD_ST;
        self.pw(regs::P_CMD, cmd);
        true
    }

    /// Build the command header (slot 0) + command table for one command and
    /// issue it on PxCI bit 0, polling for completion. `fis` is the 20-byte
    /// H2D Register FIS; `write` selects the header W bit; `bytes` is the PRDT
    /// byte count into/out of the bounce frame (≤ one page). Returns true on a
    /// clean completion (PxCI bit 0 cleared, no TFD.ERR / PxIS error).
    /// # C: O(poll until completion)
    fn issue(&mut self, fis: &[u8; 20], write: bool, bytes: u32) -> bool {
        let h = hhdm();
        if h == 0 { return false; }
        let prdtl: u32 = if bytes == 0 { 0 } else { 1 };

        // Command Header slot 0 (32 bytes, AHCI §4.2.2):
        //   dw0 = CFL|W|PRDTL, dw1 = PRDBC (0), dw2/dw3 = CTBA lo/hi.
        let clb_va = h.wrapping_add(self.clb_pa) as *mut u32;
        // SAFETY: HHDM-mapped command-list frame we own (1 KiB used of one
        // page); slot 0 occupies dwords 0..8; aligned 32-bit stores publish
        // the header before the PxCI doorbell. ctba is HBA-readable PA.
        unsafe {
            core::ptr::write_volatile(clb_va.add(0),
                regs::cmd_header_dw0(CFL_DWORDS, write, prdtl));
            core::ptr::write_volatile(clb_va.add(1), 0); // PRDBC
            core::ptr::write_volatile(clb_va.add(2), (self.ctba_pa & 0xFFFF_FFFF) as u32);
            core::ptr::write_volatile(clb_va.add(3), (self.ctba_pa >> 32) as u32);
            for i in 4..8 { core::ptr::write_volatile(clb_va.add(i), 0); }
        }

        // Command Table: CFIS at byte 0, PRDT entry 0 at byte 0x80
        //   (DBA lo, DBA hi, reserved, DBC|I where DBC = byte_count-1).
        let ct_va = h.wrapping_add(self.ctba_pa) as *mut u8;
        // SAFETY: HHDM-mapped command-table frame we own (128 B CFIS region +
        // one 16-byte PRDT entry, well within one page); byte stores of the
        // CFIS then aligned dword stores of the PRDT entry, published before
        // the doorbell. bounce_pa is an HBA-readable/writable PA.
        unsafe {
            // Zero the CFIS region then copy the H2D FIS in.
            for i in 0..CT_PRDT_OFF { core::ptr::write_volatile(ct_va.add(i), 0); }
            for (i, b) in fis.iter().enumerate() { core::ptr::write_volatile(ct_va.add(i), *b); }
            if prdtl != 0 {
                let prdt = ct_va.add(CT_PRDT_OFF) as *mut u32;
                core::ptr::write_volatile(prdt.add(0), (self.bounce_pa & 0xFFFF_FFFF) as u32);
                core::ptr::write_volatile(prdt.add(1), (self.bounce_pa >> 32) as u32);
                core::ptr::write_volatile(prdt.add(2), 0); // reserved
                // DBC = byte count - 1 (bits 21:0); bit 31 = I (interrupt).
                core::ptr::write_volatile(prdt.add(3), (bytes - 1) & 0x003F_FFFF);
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        // Clear interrupt status, issue command slot 0.
        self.pw(regs::P_IS, 0xFFFF_FFFF);
        self.pw(regs::P_CI, 1 << 0);

        // Poll PxCI bit 0 clear; bail on TFD.ERR or a fatal PxIS bit.
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        loop {
            let ci = self.pr(regs::P_CI);
            let tfd = self.pr(regs::P_TFD);
            if tfd & regs::TFD_ERR != 0 { return false; }
            if ci & (1 << 0) == 0 {
                // Completed: a final TFD.ERR check covers a device error that
                // cleared CI on the same poll.
                return self.pr(regs::P_TFD) & regs::TFD_ERR == 0;
            }
            if now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// IDENTIFY DEVICE (0xEC): DMA the 512-byte (256-word) data into the
    /// bounce frame, decode sector count + size. # C: O(one command)
    fn identify(&mut self) -> bool {
        let fis = regs::h2d_fis(regs::ATA_IDENTIFY, 0, 0, 0);
        if !self.issue(&fis, false, 512) { return false; }
        let h = hhdm();
        let p = h.wrapping_add(self.bounce_pa) as *const u16;
        let mut words = [0u16; 256];
        // SAFETY: HHDM-mapped bounce frame the device just filled with the
        // 512-byte IDENTIFY data; aligned u16 loads of all 256 words stay
        // within the one-page frame.
        unsafe { for i in 0..256 { words[i] = core::ptr::read_volatile(p.add(i)); } }
        self.sectors = regs::identify_sector_count(&words);
        self.blk_size = regs::identify_sector_size(&words);
        let (serial, serial_len) = regs::identify_serial(&words);
        self.serial = if serial_len == 0 {
            None
        } else {
            let mut s = String::new();
            for b in &serial[..serial_len] {
                s.push(*b as char);
            }
            Some(s)
        };
        self.sectors > 0
    }

    /// Issue one READ (0x25) or WRITE (0x35) DMA EXT for `count` sectors at
    /// `lba`, data through the bounce frame (≤ one page). The caller stages
    /// writes into / copies reads out of the bounce frame around this call.
    /// # C: O(one command)
    pub fn rw(&mut self, write: bool, lba: u64, count: u16) -> bool {
        let cmd = if write { regs::ATA_WRITE_DMA_EXT } else { regs::ATA_READ_DMA_EXT };
        let fis = regs::h2d_fis(cmd, lba, count, regs::ATA_DEV_LBA);
        let bytes = (count as u32) * self.blk_size;
        self.issue(&fis, write, bytes)
    }

    /// FLUSH CACHE EXT (0xEA): durable-write barrier. # C: O(one command)
    pub fn flush(&mut self) -> bool {
        let fis = regs::h2d_fis(regs::ATA_FLUSH_EXT, 0, 0, regs::ATA_DEV_LBA);
        self.issue(&fis, false, 0)
    }

    /// HHDM VA of the bounce frame, for staging/copying I/O payloads. # C: O(1)
    pub fn bounce_va(&self) -> u64 { hhdm().wrapping_add(self.bounce_pa) }
}
