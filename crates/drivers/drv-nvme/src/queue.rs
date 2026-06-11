// NVMe controller bring-up + admin/IO queue mechanics (kernel-only — pure
// MMIO + HHDM, so this file is `cfg(target_os = "oxide-kernel")`; the math it
// uses lives in `regs.rs` and host-tests). Mirrors drv-virtio-blk/src/modern:
// the boot probe maps BAR0 and hands the register-file VA here; this module
// owns reset → admin queues → IDENTIFY → one I/O queue pair → READ/WRITE.
//
// Single I/O queue pair, one in-flight command at a time, serialised by the
// caller's Spinlock (see lib.rs). Completion is polled on the CQ phase bit.

#![cfg(target_os = "oxide-kernel")]

use crate::regs;

/// HHDM base for the running arch (PA→VA for queue + PRP frames).
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

/// Monotonic wall-clock ns (0 if unsupported) — bounds the RDY + completion
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

/// Worst-case wait for an admin/IO completion. CAP.TO bounds RDY transitions;
/// this caps a genuinely-lost completion to EIO. 5 s is generous for QEMU.
const IO_TIMEOUT_NS: u64 = 5_000_000_000;

/// Entries per admin + I/O queue. 32 fits one 4 KiB SQ frame (32×64=2 KiB)
/// and one CQ frame (32×16=512 B) with room to spare, and is ≤ CAP.MQES on
/// QEMU. Power of two so head/tail wrap is a mask.
pub const Q_ENTRIES: u32 = 32;

/// One queue pair: a submission queue (64-byte entries) and a completion
/// queue (16-byte entries), each one PMM frame. `cid` is the rolling command
/// identifier; `cq_phase` is the expected phase bit (toggles each wrap).
struct Queue {
    sq_pa:   u64,
    cq_pa:   u64,
    sq_tail: u32,
    cq_head: u32,
    cq_phase: bool,
    /// Doorbell register VAs (BAR0 + doorbell_off).
    sq_db_va: u64,
    cq_db_va: u64,
    cid:      u16,
}

/// The NVMe controller bring-up state. Holds the BAR0 register-file VA, the
/// admin + single I/O queue, and the negotiated geometry (namespace block
/// size + capacity). One PRP bounce frame bounds a request to one transfer.
pub struct Nvme {
    bar0_va: u64,
    dstrd:   u32,
    admin:   Queue,
    io:      Queue,
    /// PRP bounce frame (one 4 KiB page) — the data buffer for one I/O.
    prp_pa:  u64,
    /// Namespace 1 geometry harvested at IDENTIFY.
    pub ns_blocks: u64,
    pub blk_size:  u32,
}

// SAFETY justification: Nvme holds raw PAs/VAs into HHDM/MMIO stable for the
// controller's lifetime; all mutable queue access is serialised by the
// Spinlock the owner (lib.rs NvmeBlk) wraps it in, so cross-CPU sharing is
// sound — no interior mutation escapes that lock.
unsafe impl Send for Nvme {}
unsafe impl Sync for Nvme {}

/// 4 KiB host/PRP page size (CC.MPS=0). One PRP entry covers one page.
const PAGE: u64 = 0x1000;

impl Nvme {
    /// Read a 32-bit controller register. # C: O(1)
    #[inline]
    fn r32(&self, off: u64) -> u32 {
        // SAFETY: bar0_va is the Device-attr-mapped NVMe register file
        // (map_mmio_pages, 2 pages); `off` is a spec register offset within
        // the first page; aligned 32-bit MMIO load of a controller register.
        unsafe { core::ptr::read_volatile((self.bar0_va + off) as *const u32) }
    }
    /// Write a 32-bit controller register. # C: O(1)
    #[inline]
    fn w32(&self, off: u64, val: u32) {
        // SAFETY: bar0_va is the Device-attr-mapped NVMe register file; `off`
        // is a spec register offset within the mapped window; aligned 32-bit
        // MMIO store to a controller register the driver exclusively owns.
        unsafe { core::ptr::write_volatile((self.bar0_va + off) as *mut u32, val); }
    }
    /// Write a 64-bit controller register as two 32-bit halves (some MMIO
    /// fabrics reject a 64-bit store to config space). # C: O(1)
    #[inline]
    fn w64(&self, off: u64, val: u64) {
        self.w32(off, (val & 0xFFFF_FFFF) as u32);
        self.w32(off + 4, (val >> 32) as u32);
    }
    /// Read CAP (64-bit) as two halves. # C: O(1)
    #[inline]
    fn cap(&self) -> u64 {
        (self.r32(regs::REG_CAP) as u64)
            | ((self.r32(regs::REG_CAP + 4) as u64) << 32)
    }

    /// Zero a freshly-allocated queue/PRP frame via HHDM. # C: O(page)
    fn zero_frame(pa: u64) {
        let h = hhdm();
        if h == 0 || pa == 0 { return; }
        let va = h.wrapping_add(pa) as *mut u8;
        // SAFETY: HHDM-mapped freshly-PMM-allocated frame we exclusively own;
        // aligned byte stores span exactly one 4 KiB page (never past the
        // frame the buddy returned), giving deterministic initial state.
        unsafe { for i in 0..(PAGE as usize) { core::ptr::write_volatile(va.add(i), 0); } }
    }

    /// Build the controller, reset it, set up the admin queues, run IDENTIFY,
    /// create the I/O queue pair. Returns None on any timeout/alloc failure.
    /// `bar0_va` is the HHDM-independent register-file VA from map_mmio_pages.
    /// # C: O(reset + 2 admin cmds + 2 create-queue cmds)
    pub fn bring_up(bar0_va: u64) -> Option<Nvme> {
        // Allocate admin SQ + CQ, I/O SQ + CQ, and the PRP bounce frame.
        let asq = pmm::setup::alloc_one_frame()?;
        let acq = pmm::setup::alloc_one_frame()?;
        let isq = pmm::setup::alloc_one_frame()?;
        let icq = pmm::setup::alloc_one_frame()?;
        let prp = pmm::setup::alloc_one_frame()?;
        for f in [asq, acq, isq, icq, prp] { Self::zero_frame(f); }

        // Pre-read DSTRD from CAP using a throwaway accessor (bar0_va direct).
        // SAFETY: bar0_va is the Device-attr-mapped register file; aligned
        // 32-bit loads of CAP's two halves to compute the doorbell stride.
        let cap = unsafe {
            (core::ptr::read_volatile((bar0_va + regs::REG_CAP) as *const u32) as u64)
            | ((core::ptr::read_volatile((bar0_va + regs::REG_CAP + 4) as *const u32) as u64) << 32)
        };
        let dstrd = regs::cap_dstrd(cap);

        let admin = Queue {
            sq_pa: asq, cq_pa: acq, sq_tail: 0, cq_head: 0, cq_phase: true,
            sq_db_va: bar0_va + regs::doorbell_off(0, false, dstrd),
            cq_db_va: bar0_va + regs::doorbell_off(0, true,  dstrd),
            cid: 0,
        };
        let io = Queue {
            sq_pa: isq, cq_pa: icq, sq_tail: 0, cq_head: 0, cq_phase: true,
            sq_db_va: bar0_va + regs::doorbell_off(1, false, dstrd),
            cq_db_va: bar0_va + regs::doorbell_off(1, true,  dstrd),
            cid: 0,
        };

        let mut nv = Nvme {
            bar0_va, dstrd, admin, io, prp_pa: prp,
            ns_blocks: 0, blk_size: 512,
        };
        let to_ms = regs::cap_to_ms(cap).max(2_000);

        // 1. Disable: CC.EN=0, wait CSTS.RDY==0.
        nv.w32(regs::REG_CC, 0);
        if !nv.wait_rdy(false, to_ms) { return None; }

        // 2. Program admin queue attributes + base addresses.
        nv.w32(regs::REG_AQA, regs::aqa(Q_ENTRIES));
        nv.w64(regs::REG_ASQ, nv.admin.sq_pa);
        nv.w64(regs::REG_ACQ, nv.admin.cq_pa);

        // 3. Enable: CC with IOSQES/IOCQES + EN, wait CSTS.RDY==1.
        nv.w32(regs::REG_CC, regs::cc_enable());
        if !nv.wait_rdy(true, to_ms) { return None; }

        // 4. IDENTIFY controller (confirm the controller answers admin cmds).
        if nv.identify(regs::CNS_CONTROLLER, 0).is_none() { return None; }

        // 5. IDENTIFY namespace 1 → capacity (NSZE) + LBA format → block size.
        if !nv.identify_ns1() { return None; }

        // 6. Create the I/O completion + submission queue (qid=1).
        if !nv.create_io_cq() { return None; }
        if !nv.create_io_sq() { return None; }

        Some(nv)
    }

    /// Poll CSTS.RDY until it equals `want`, bounded by `to_ms`. Fails on
    /// CSTS.CFS (controller fatal). # C: O(poll until RDY flips)
    fn wait_rdy(&self, want: bool, to_ms: u64) -> bool {
        let deadline = now_ns().saturating_add(to_ms.saturating_mul(1_000_000));
        loop {
            let csts = self.r32(regs::REG_CSTS);
            if csts & regs::CSTS_CFS != 0 { return false; }
            if ((csts & regs::CSTS_RDY) != 0) == want { return true; }
            if now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Write a 64-byte SQ entry into `q`'s submission queue at its tail, ring
    /// the SQ doorbell, and poll `q`'s completion queue for the matching CID.
    /// `cmd` is the 16-dword (64-byte) command image already containing the
    /// opcode in dword0 byte 0 (CID is stamped here). Returns the 16-bit
    /// status code (0 = success) or None on timeout/fatal.
    /// # C: O(poll until completion)
    fn submit(&mut self, qid_is_io: bool, mut cmd: [u32; 16]) -> Option<u16> {
        // Stamp CID into dword0 bits 31:16, advance the queue's rolling CID.
        let (sq_pa, slot, cid) = {
            let q = if qid_is_io { &mut self.io } else { &mut self.admin };
            let cid = q.cid;
            q.cid = q.cid.wrapping_add(1);
            cmd[0] = (cmd[0] & 0x0000_FFFF) | ((cid as u32) << 16);
            (q.sq_pa, q.sq_tail, cid)
        };
        let h = hhdm();
        if h == 0 { return None; }
        // Write the 64-byte command into SQ slot `slot`.
        let sq = h.wrapping_add(sq_pa) as *mut u32;
        // SAFETY: HHDM-mapped admin/IO SQ frame we own; `slot` < Q_ENTRIES so
        // the 16-dword command stays within the frame (32×64B = 2 KiB ≤ page);
        // aligned 32-bit stores publish the command before the doorbell kick.
        unsafe {
            let base = (slot as usize) * 16;
            for (i, w) in cmd.iter().enumerate() {
                core::ptr::write_volatile(sq.add(base + i), *w);
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        // Advance + ring the SQ tail doorbell.
        let (sq_db, cq_pa, cq_db) = {
            let q = if qid_is_io { &mut self.io } else { &mut self.admin };
            q.sq_tail = (q.sq_tail + 1) % Q_ENTRIES;
            (q.sq_db_va, q.cq_pa, q.cq_db_va)
        };
        // SAFETY: sq_db is BAR0 + doorbell_off, a Device-attr MMIO doorbell;
        // aligned 32-bit store of the new SQ tail index rings the controller.
        unsafe { core::ptr::write_volatile(sq_db as *mut u32, self.sq_tail_of(qid_is_io)); }

        self.poll_cq(qid_is_io, cq_pa, cq_db, h, cid)
    }

    /// Current SQ tail of the selected queue (post-advance). # C: O(1)
    #[inline]
    fn sq_tail_of(&self, qid_is_io: bool) -> u32 {
        if qid_is_io { self.io.sq_tail } else { self.admin.sq_tail }
    }

    /// Poll the completion queue for the entry whose CID matches `cid` and
    /// whose phase bit matches the expected phase, then advance + ring the CQ
    /// head doorbell. Returns the status code. # C: O(poll until completion)
    fn poll_cq(&mut self, qid_is_io: bool, cq_pa: u64, cq_db: u64, h: u64, cid: u16) -> Option<u16> {
        let cq = h.wrapping_add(cq_pa) as *const u32;
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        loop {
            let (head, phase) = {
                let q = if qid_is_io { &self.io } else { &self.admin };
                (q.cq_head, q.cq_phase)
            };
            let base = (head as usize) * 4; // 16-byte CQE = 4 dwords
            // SAFETY: HHDM-mapped CQ frame we own; `head` < Q_ENTRIES so the
            // 4-dword CQE stays in the frame; aligned 32-bit loads of the
            // status/CID dwords the controller wrote.
            let (d2, d3) = unsafe {
                (core::ptr::read_volatile(cq.add(base + 2)),
                 core::ptr::read_volatile(cq.add(base + 3)))
            };
            let (cqe_phase, status_code, cqe_cid) = regs::cqe_decode(d2, d3);
            if cqe_phase == phase {
                // Advance head; wrap toggles the expected phase.
                let nh = (head + 1) % Q_ENTRIES;
                let new_phase = if nh == 0 { !phase } else { phase };
                {
                    let q = if qid_is_io { &mut self.io } else { &mut self.admin };
                    q.cq_head = nh;
                    q.cq_phase = new_phase;
                }
                // SAFETY: cq_db is BAR0 + doorbell_off, a Device-attr MMIO
                // doorbell; aligned 32-bit store of the new CQ head index.
                unsafe { core::ptr::write_volatile(cq_db as *mut u32, nh); }
                if cqe_cid != cid { return Some(0xFFFF); } // out-of-order: treat as error
                return Some(status_code);
            }
            if now_ns() >= deadline { return None; }
            core::hint::spin_loop();
        }
    }

    /// IDENTIFY (opcode 0x06): DMA a 4 KiB structure into the PRP bounce
    /// frame. `cns` selects controller (1) / namespace (0); `nsid` is the
    /// namespace id (0 for controller). Returns Some(prp_va) on success so
    /// the caller can read fields, None on failure. # C: O(one admin cmd)
    fn identify(&mut self, cns: u32, nsid: u32) -> Option<u64> {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::ADMIN_IDENTIFY as u32;     // opcode (CID stamped in submit)
        cmd[1] = nsid;                            // NSID
        cmd[6] = (self.prp_pa & 0xFFFF_FFFF) as u32; // PRP1 low
        cmd[7] = (self.prp_pa >> 32) as u32;         // PRP1 high
        cmd[10] = cns;                            // CDW10: CNS
        let status = self.submit(false, cmd)?;
        if status != 0 { return None; }
        Some(hhdm().wrapping_add(self.prp_pa))
    }

    /// IDENTIFY namespace 1 and harvest NSZE (capacity in blocks) + the
    /// in-use LBA format's block size. NVMe §5.15.2.1: NSZE @ byte 0 (u64),
    /// FLBAS @ byte 26 (low 4 bits = active LBAF index), LBAF array @ byte
    /// 128 (16 × u32). # C: O(one admin cmd)
    fn identify_ns1(&mut self) -> bool {
        let va = match self.identify(regs::CNS_NAMESPACE, 1) { Some(v) => v, None => return false };
        // SAFETY: HHDM-mapped PRP frame the controller just filled with the
        // Identify-Namespace structure; aligned reads of NSZE/FLBAS/LBAF stay
        // within the 4 KiB page (offsets 0, 26, 128+idx*4 < 4096).
        unsafe {
            let p = va as *const u8;
            let mut nsze = 0u64;
            for i in 0..8 { nsze |= (core::ptr::read_volatile(p.add(i)) as u64) << (8 * i); }
            let flbas = core::ptr::read_volatile(p.add(26));
            let idx = (flbas & 0x0F) as usize;
            let lbaf_p = (va + 128 + (idx as u64) * 4) as *const u32;
            let lbaf = core::ptr::read_volatile(lbaf_p);
            self.ns_blocks = nsze;
            self.blk_size = regs::lba_size_from_lbaf(lbaf);
        }
        self.ns_blocks > 0
    }

    /// CREATE I/O COMPLETION QUEUE (opcode 0x05) for qid=1: PRP1 = CQ PA,
    /// CDW10 = ((size-1)<<16)|qid, CDW11 = PC bit (physically contiguous).
    /// # C: O(one admin cmd)
    fn create_io_cq(&mut self) -> bool {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::ADMIN_CREATE_IO_CQ as u32;
        cmd[6] = (self.io.cq_pa & 0xFFFF_FFFF) as u32;
        cmd[7] = (self.io.cq_pa >> 32) as u32;
        cmd[10] = ((Q_ENTRIES - 1) << 16) | 1;   // QSIZE (0-based) | QID=1
        cmd[11] = 0x1;                           // PC=1 (no interrupts: IEN=0)
        self.submit(false, cmd) == Some(0)
    }

    /// CREATE I/O SUBMISSION QUEUE (opcode 0x01) for qid=1, bound to CQ 1:
    /// PRP1 = SQ PA, CDW10 = ((size-1)<<16)|qid, CDW11 = (cqid<<16)|PC.
    /// # C: O(one admin cmd)
    fn create_io_sq(&mut self) -> bool {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::ADMIN_CREATE_IO_SQ as u32;
        cmd[6] = (self.io.sq_pa & 0xFFFF_FFFF) as u32;
        cmd[7] = (self.io.sq_pa >> 32) as u32;
        cmd[10] = ((Q_ENTRIES - 1) << 16) | 1;   // QSIZE (0-based) | QID=1
        cmd[11] = (1u32 << 16) | 0x1;            // CQID=1 | PC=1
        self.submit(false, cmd) == Some(0)
    }

    /// Max bytes one `rw` call transfers: two PRP entries (PRP1 + PRP2) each
    /// one page, all backed by the single bounce frame's first/second halves
    /// is NOT how PRP works (PRP2 must be a distinct page). We bound to ONE
    /// page (PRP1 only) so a request never needs a PRP list. The BlockDevice
    /// layer in lib.rs loops per-chunk. # C: O(1)
    pub const MAX_XFER: u64 = PAGE;

    /// Issue one READ (0x02) or WRITE (0x01) on the I/O queue for namespace 1.
    /// `slba` = starting LBA, `nlb_minus_1` = (block count − 1), data moves
    /// through the PRP bounce frame (≤ one page). The caller stages writes
    /// into / copies reads out of the bounce frame around this call.
    /// # C: O(one I/O cmd)
    pub fn rw(&mut self, write: bool, slba: u64, nlb_minus_1: u16) -> bool {
        let mut cmd = [0u32; 16];
        cmd[0] = if write { regs::IO_WRITE } else { regs::IO_READ } as u32;
        cmd[1] = 1;                               // NSID = 1
        cmd[6] = (self.prp_pa & 0xFFFF_FFFF) as u32; // PRP1 low
        cmd[7] = (self.prp_pa >> 32) as u32;         // PRP1 high
        cmd[10] = (slba & 0xFFFF_FFFF) as u32;    // CDW10 SLBA low
        cmd[11] = (slba >> 32) as u32;            // CDW11 SLBA high
        cmd[12] = nlb_minus_1 as u32;             // CDW12 NLB (0-based)
        self.submit(true, cmd) == Some(0)
    }

    /// FLUSH (opcode 0x00) on the I/O queue for namespace 1. # C: O(one cmd)
    pub fn flush(&mut self) -> bool {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::IO_FLUSH as u32;
        cmd[1] = 1; // NSID = 1
        self.submit(true, cmd) == Some(0)
    }

    /// HHDM VA of the PRP bounce frame, for staging/copying I/O payloads.
    /// # C: O(1)
    pub fn prp_va(&self) -> u64 { hhdm().wrapping_add(self.prp_pa) }
}
