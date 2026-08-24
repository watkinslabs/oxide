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

use alloc::{string::String, sync::Arc};

use crate::host::AhciHost;
use crate::lifecycle::{self, RuntimeRecoveryStep};
use crate::regs;

/// HHDM base for the running arch (PA→VA for HBA DMA structures + data run).
/// # C: O(1)
#[inline]
pub(crate) fn hhdm() -> u64 {
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
pub(crate) fn now_ns() -> u64 {
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
const DATA_ORDER: pmm::Order = pmm::Order(9);
const DATA_BYTES: u64 = PAGE << DATA_ORDER.0;

/// Worst-case wait for a command completion or a port stop. 5 s is generous
/// for QEMU's emulated AHCI; bounds a genuinely-lost completion to EIO.
const IO_TIMEOUT_NS: u64 = 5_000_000_000;
/// Per-port SATA PHY link-up timeout after COMRESET (bounded so empty ports
/// don't stall boot; a real link establishes in well under this).
const LINK_TIMEOUT_NS: u64 = 200_000_000;

/// The AHCI controller bring-up state for one SATA-disk port. Holds the ABAR
/// register-file VA, the port index, the DMA-structure PAs (command list,
/// received-FIS, command table, DMA data run), and the negotiated geometry.
pub struct Ahci {
    host: Arc<AhciHost>,
    port:    u32,
    pub(crate) clb_pa:  u64,  // command list (1 KiB, 1 KiB-aligned)
    pub(crate) clb_dma: u64,
    fb_pa:   u64,  // received FIS (256 B, 256 B-aligned)
    fb_dma:  u64,
    pub(crate) ctba_pa: u64,  // command table for slot 0 (128 B header + PRDT)
    pub(crate) ctba_dma: u64,
    /// Contiguous DMA data run used by one I/O command.
    pub(crate) data_pa: u64,
    pub(crate) data_dma: u64,
    /// Disk geometry harvested at IDENTIFY.
    pub sectors:   u64,
    pub blk_size:  u32,
    /// ATA IDENTIFY DEVICE serial, if the device reports a non-padding value.
    pub serial:    Option<String>,
    /// Native-order bytes of the ATA IDENTIFY DEVICE page retained for its
    /// user ABI owner after probe and runtime recovery.
    pub identity:  [u8; 512],
}

// SAFETY justification: Ahci holds raw PAs/VAs into HHDM/MMIO stable for the
// device's lifetime; all mutable port access is serialised by the Spinlock
// the owner (lib.rs AhciBlk) wraps it in, so cross-CPU sharing is sound — no
// interior mutation escapes that lock.
unsafe impl Send for Ahci {}
unsafe impl Sync for Ahci {}

impl Ahci {
    /// ATA IDENTIFY word 85 bit 5: write-cache feature is enabled.
    pub(crate) fn write_cache_enabled(&self) -> bool {
        let word = u16::from_le_bytes([self.identity[170], self.identity[171]]);
        word & (1 << 5) != 0
    }
    fn free_frame(pa: &mut u64) {
        if *pa == 0 {
            return;
        }
        // SAFETY: the caller has stopped/quiesced the port. These frames are
        // command/FIS/table frames returned by alloc_raw_frame during bring-up.
        unsafe { pmm::setup::free_one_frame(*pa); }
        *pa = 0;
    }

    fn alloc_frames() -> Result<([u64; 3], u64), &'static str> {
        let mut frames = [0u64; 3];
        let names = ["alloc clb", "alloc fb", "alloc ct"];
        let mut i = 0usize;
        while i < frames.len() {
            match pmm::setup::alloc_raw_frame() {
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
        let Some(data_pa) = pmm::setup::alloc_contig(DATA_ORDER) else {
            for pa in frames.iter_mut() { Self::free_frame(pa); }
            return Err("alloc data run");
        };
        Ok((frames, data_pa))
    }

    fn release_unstarted(bdf: pci::Bdf, frames: &mut [u64; 3], dmas: &mut [u64; 3], data_pa: u64, data_dma: u64) {
        for (pa, dma) in frames.iter_mut().zip(dmas.iter_mut()) {
            if *dma != 0 { let _ = iommu::unmap_dma(bdf, *dma, PAGE as usize); *dma = 0; }
            Self::free_frame(pa);
        }
        if data_dma != 0 { let _ = iommu::unmap_dma(bdf, data_dma, DATA_BYTES as usize); }
        if data_pa != 0 {
            // SAFETY: no command list was programmed, so the HBA cannot DMA this allocation.
            unsafe { pmm::setup::free_contig(data_pa, DATA_ORDER); }
        }
    }

    /// Stop the active port and return command/FIS/table/data DMA memory to PMM.
    /// Publication must already be removed, or the system must be in terminal
    /// shutdown, and callers quiesced.
    /// # C: O(port stop wait + DMA data run frees)
    pub fn shutdown_and_free(&mut self) {
        if self.host.abar_va() != 0 {
            let _ = self.stop_port();
            self.pw(regs::P_CLB, 0);
            self.pw(regs::P_CLBU, 0);
            self.pw(regs::P_FB, 0);
            self.pw(regs::P_FBU, 0);
        }
        if iommu::unmap_dma(self.host.bdf(), self.clb_dma, PAGE as usize) { Self::free_frame(&mut self.clb_pa); self.clb_dma = 0; }
        if iommu::unmap_dma(self.host.bdf(), self.fb_dma, PAGE as usize) { Self::free_frame(&mut self.fb_pa); self.fb_dma = 0; }
        if iommu::unmap_dma(self.host.bdf(), self.ctba_dma, PAGE as usize) { Self::free_frame(&mut self.ctba_pa); self.ctba_dma = 0; }
        if self.data_pa != 0 && iommu::unmap_dma(self.host.bdf(), self.data_dma, DATA_BYTES as usize) {
            // SAFETY: port stop above prevents DMA and `data_pa` belongs to
            // this controller's `alloc_contig(DATA_ORDER)` allocation.
            unsafe { pmm::setup::free_contig(self.data_pa, DATA_ORDER); }
            self.data_pa = 0;
            self.data_dma = 0;
        }
    }

    /// Bytes one transfer carries in the contiguous PRDT data run. # C: O(1)
    pub const MAX_XFER: u64 = DATA_BYTES;

    /// HHDM VA of this port's controller-owned receive-FIS page. # C: O(1)
    pub(crate) fn receive_fis_va(&self) -> u64 { hhdm().wrapping_add(self.fb_pa) }

    /// Read a 32-bit HBA/port register at ABAR + `off`. # C: O(1)
    #[inline]
    pub(crate) fn r32(&self, off: u64) -> u32 {
        // SAFETY: abar_va is the Device-attr-mapped AHCI register file
        // (map_mmio_pages, 2 pages); `off` is a spec HBA/port register offset
        // within the mapped window; aligned 32-bit MMIO load.
        self.host.r32(off)
    }
    /// Write a 32-bit HBA/port register at ABAR + `off`. # C: O(1)
    #[inline]
    pub(crate) fn w32(&self, off: u64, val: u32) {
        // SAFETY: abar_va is the Device-attr-mapped AHCI register file; `off`
        // is a spec HBA/port register offset within the mapped window; aligned
        // 32-bit MMIO store to a register the driver exclusively owns.
        self.host.w32(off, val);
    }
    /// Read a 32-bit per-port register of this port. # C: O(1)
    #[inline]
    pub(crate) fn pr(&self, reg: u64) -> u32 { self.r32(regs::port_reg(self.port, reg)) }
    /// Write a 32-bit per-port register of this port. # C: O(1)
    #[inline]
    pub(crate) fn pw(&self, reg: u64, val: u32) { self.w32(regs::port_reg(self.port, reg), val); }

    /// Device-mapped ABAR VA retained for hard-handler publication. # C: O(1)
    pub(crate) fn abar_va(&self) -> u64 { self.host.abar_va() }

    /// Complete page-rounded BAR5 aperture retained by this controller. # C: O(1)
    pub(crate) fn abar_map_bytes(&self) -> u64 { self.host.abar_map_bytes() }

    /// Offset from the owned mapping base to BAR5. # C: O(1)
    pub(crate) fn abar_offset(&self) -> u64 { self.host.abar_offset() }

    /// Retain the controller while this port changes between media watcher and
    /// published-disk ownership. # C: O(1)
    pub(crate) fn host_clone(&self) -> Arc<AhciHost> { self.host.clone() }

    /// Controller retained by this port. # C: O(1)
    pub(crate) fn host(&self) -> &AhciHost { &self.host }

    /// Selected SATA port index. # C: O(1)
    pub(crate) fn port_index(&self) -> u32 { self.port }

    /// Sample the SATA PHY state after a connect/PHY-ready notification.
    /// The caller decides media lifecycle from this live register value rather
    /// than inferring removal from an interrupt cause alone. # C: O(1)
    pub(crate) fn link_is_online(&self) -> bool {
        regs::link_is_online(self.pr(regs::P_SSTS))
    }

    /// W1C the selected port cause before its global level latch. # C: O(1)
    pub(crate) fn clear_command_interrupts(&self) {
        self.pw(regs::P_IS, u32::MAX);
        self.host.clear_interrupts(1 << self.port);
    }

    /// Enable Linux-shaped command/error port causes and global IRQs. # C: O(1)
    pub(crate) fn enable_interrupts(&self) {
        self.clear_command_interrupts();
        self.pw(regs::P_IE, regs::PIS_ENABLE);
        self.host.enable_interrupts(1 << self.port);
    }

    /// Mask port/global causes and clear their retained latches. # C: O(1)
    pub(crate) fn disable_interrupts(&self) {
        self.pw(regs::P_IE, 0);
        let _ = self.pr(regs::P_IE);
        self.host.disable_interrupts(1 << self.port);
    }

    fn comreset_link(&self) -> bool {
        let s = self.pr(regs::P_SCTL);
        self.pw(regs::P_SCTL, (s & !regs::SSTS_DET_MASK) | 1);
        let hold = now_ns().saturating_add(2_000_000);
        while now_ns() < hold { core::hint::spin_loop(); }
        let s = self.pr(regs::P_SCTL);
        self.pw(regs::P_SCTL, s & !regs::SSTS_DET_MASK);
        let deadline = now_ns().saturating_add(LINK_TIMEOUT_NS);
        loop {
            if self.link_is_online() { return true; }
            if now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Freeze a failed runtime command, reset its PHY, and thaw only if the
    /// same ATA disk re-identifies with the published geometry. # C: O(reset)
    pub(crate) fn recover_runtime(&mut self, capacity: u64, blk_size: u32) -> bool {
        let mut ok = true;
        for step in lifecycle::runtime_recovery_steps() {
            if !ok { break; }
            ok = match step {
                RuntimeRecoveryStep::FreezePortIrq => { self.disable_interrupts(); true }
                RuntimeRecoveryStep::StopEngine => self.stop_port(),
                RuntimeRecoveryStep::Comreset => self.comreset_link(),
                RuntimeRecoveryStep::ClearError => {
                    self.pw(regs::P_SERR, u32::MAX);
                    self.pw(regs::P_IS, u32::MAX);
                    true
                }
                RuntimeRecoveryStep::StartEngine => self.start_port(),
                RuntimeRecoveryStep::Reidentify => {
                    self.pr(regs::P_SIG) == regs::SIG_SATA_DISK
                        && self.identify()
                        && self.sectors == capacity
                        && self.blk_size == blk_size
                }
                RuntimeRecoveryStep::ThawPortIrq => { self.enable_interrupts(); true }
            };
        }
        ok
    }

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

    /// Bring up one implemented SATA port, run IDENTIFY, and return its
    /// per-port command/DMA state. The caller owns host reset and scans every
    /// bit in the host's Ports Implemented map. # C: O(port reset + IDENTIFY)
    pub(crate) fn bring_up(host: Arc<AhciHost>, port: u32) -> Result<Ahci, &'static str> {
        if host.ports() & (1 << port) == 0 { return Err("port not implemented"); }
        let cap = host.cap();

        // The SATA PHY link is not necessarily established immediately after
        // controller reset. Drive COMRESET for this port and wait for link-up.
        // The SATA PHY link (PxSSTS.DET) is not necessarily established just by
        // enabling AHCI: on some hosts (notably the aarch64 virt machine) the
        // port presents no link until the guest drives a COMRESET. So for each
        // implemented port issue a COMRESET (PxSCTL.DET=1, hold ≥1ms, DET=0)
        // then wait for the PHY link (PxSSTS.DET==3) — the Linux libata reset
        // sequence (AHCI §10.1.2 / SATA §). Bounded so an empty port can't
        // stall boot.
        {
            let a = Ahci {
                host: host.clone(), port,
                clb_pa: 0, clb_dma: 0, fb_pa: 0, fb_dma: 0, ctba_pa: 0, ctba_dma: 0, data_pa: 0, data_dma: 0,
                sectors: 0, blk_size: 512, serial: None, identity: [0; 512],
            };
            if !a.comreset_link() { return Err("no SATA disk"); }
            // Device present + PHY up. Do NOT gate on PxSIG here: the signature
            // register is only populated from the device's first D2H register
            // FIS, which arrives after FRE is enabled (in start_port below) —
            // x86 QEMU pre-populates it, aarch64 virt does not. Select on the
            // live link and let IDENTIFY confirm it's an ATA disk (libata does
            // the same: link first, classify after the reset/FIS).
        }

        // Allocate per-port command/FIS structures plus a contiguous data
        // run. The single PRDT entry can describe this whole 2 MiB run.
        let (mut frames, data_pa) = Self::alloc_frames()?;
        let dma_mask = regs::dma_mask(cap);
        let mut dmas = [0u64; 3];
        for (pa, dma) in frames.iter().zip(dmas.iter_mut()) {
            match iommu::map_dma_below(host.bdf(), *pa, PAGE as usize, dma_mask) {
                Some(mapped) => *dma = mapped,
                None => {
                    Self::release_unstarted(host.bdf(), &mut frames, &mut dmas, data_pa, 0);
                    return Err("DMA map frame");
                }
            }
        }
        let Some(data_dma) = iommu::map_dma_below(host.bdf(), data_pa, DATA_BYTES as usize, dma_mask) else {
            Self::release_unstarted(host.bdf(), &mut frames, &mut dmas, data_pa, 0);
            return Err("DMA map data");
        };
        if !dmas.iter().all(|dma| regs::dma_range_fits(cap, *dma, PAGE))
            || !regs::dma_range_fits(cap, data_dma, DATA_BYTES) {
            Self::release_unstarted(host.bdf(), &mut frames, &mut dmas, data_pa, data_dma);
            return Err("DMA address exceeds HBA mask");
        }
        let [clb, fb, ct] = frames;
        for f in [clb, fb, ct] { Self::zero_frame(f); }
        for page in 0..(DATA_BYTES / PAGE) { Self::zero_frame(data_pa + page * PAGE); }

        let mut a = Ahci {
            host, port,
            clb_pa: clb, clb_dma: dmas[0], fb_pa: fb, fb_dma: dmas[1], ctba_pa: ct, ctba_dma: dmas[2], data_pa, data_dma,
            sectors: 0, blk_size: 512, serial: None, identity: [0; 512],
        };

        // Stop the port, program the bases, restart it.
        if !a.stop_port() {
            a.shutdown_and_free();
            return Err("stop_port timeout");
        }
        a.pw(regs::P_CLB,  (a.clb_dma & 0xFFFF_FFFF) as u32);
        a.pw(regs::P_CLBU, (a.clb_dma >> 32) as u32);
        a.pw(regs::P_FB,   (a.fb_dma & 0xFFFF_FFFF) as u32);
        a.pw(regs::P_FBU,  (a.fb_dma >> 32) as u32);
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

}
