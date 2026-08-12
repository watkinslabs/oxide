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
use crate::platform::{hhdm, now_ns};
use mmio_map::Mapping;

/// Worst-case wait for an admin/IO completion. CAP.TO bounds RDY transitions;
/// this caps a genuinely-lost completion to EIO. 5 s is generous for QEMU.
const IO_TIMEOUT_NS: u64 = 5_000_000_000;

/// Desired queue depth. 32 fits one 4 KiB SQ frame (32×64=2 KiB) and one CQ
/// frame (32×16=512 B). Admin uses it directly; I/O is clamped to CAP.MQES.
pub const Q_ENTRIES: u32 = 32;

/// One queue pair: a submission queue (64-byte entries) and a completion
/// queue (16-byte entries), each one PMM frame. `cid` is the rolling command
/// identifier; `cq_phase` is the expected phase bit (toggles each wrap).
struct Queue {
    sq_pa:   u64,
    sq_dma:  u64,
    cq_pa:   u64,
    cq_dma:  u64,
    entries: u32,
    sq_tail: u32,
    cq_head: u32,
    cq_phase: bool,
    /// Doorbell register VAs (BAR0 + doorbell_off).
    sq_db_va: u64,
    cq_db_va: u64,
    cid:      u16,
}

/// One I/O command submitted to the sole live queue slot.
#[derive(Clone, Copy)]
pub struct IoPending { cid: u16 }

/// The NVMe controller bring-up state. Holds the BAR0 register-file VA, the
/// admin + single I/O queue, and the negotiated geometry (namespace block
/// size + capacity). One PRP bounce frame bounds a request to one transfer.
pub struct Nvme {
    bdf:     pci::Bdf,
    mmio:    Mapping,
    bar0_va: u64,
    admin:   Queue,
    io:      Queue,
    /// Contiguous data run for one serialized I/O request.
    data_pa: u64,
    data_dma: u64,
    /// One PRP-list page used once the transfer needs more than two pages.
    prp_list_pa: u64,
    prp_list_dma: u64,
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
const PAGE: u64 = regs::NVME_PAGE_BYTES;
const DATA_ORDER: pmm::Order = pmm::Order(9);
const DATA_PAGES: u64 = regs::MAX_PRP_DATA_PAGES;

impl Nvme {
    pub(crate) fn io_cq_cursor(&self) -> (u64, u32, bool) { (self.io.cq_pa, self.io.cq_head, self.io.cq_phase) }
    fn free_frame(bdf: pci::Bdf, pa: &mut u64, dma: &mut u64) {
        if *pa == 0 || !iommu::unmap_dma(bdf, *dma, PAGE as usize) {
            return;
        }
        // SAFETY: the caller owns controller teardown/quiesce. These frames
        // are the single-page queue/PRP allocations returned by alloc_one_frame
        // during bring-up and are no longer reachable by live DMA.
        unsafe { pmm::setup::free_one_frame(*pa); }
        *pa = 0;
        *dma = 0;
    }

    fn alloc_frames(bdf: pci::Bdf) -> Option<([u64; 5], [u64; 5], u64, u64)> {
        let mut frames = [0u64; 5]; let mut dmas = [0u64; 5];
        let mut i = 0usize;
        while i < frames.len() {
            match pmm::setup::alloc_one_frame() {
                Some(pa) => match iommu::map_dma(bdf, pa, PAGE as usize) { Some(dma) => { frames[i] = pa; dmas[i] = dma; }, None => { unsafe { pmm::setup::free_one_frame(pa); } for (pa, dma) in frames.iter_mut().zip(dmas.iter_mut()) { Self::free_frame(bdf, pa, dma); } return None; } },
                None => {
                    for (pa, dma) in frames.iter_mut().zip(dmas.iter_mut()) {
                        Self::free_frame(bdf, pa, dma);
                    }
                    return None;
                }
            }
            i += 1;
        }
        let Some(data_pa) = pmm::setup::alloc_contig(DATA_ORDER) else {
            for (pa, dma) in frames.iter_mut().zip(dmas.iter_mut()) { Self::free_frame(bdf, pa, dma); }
            return None;
        };
        let bytes = (DATA_PAGES * PAGE) as usize;
        let Some(data_dma) = iommu::map_dma(bdf, data_pa, bytes) else { unsafe { pmm::setup::free_contig(data_pa, DATA_ORDER); } for (pa, dma) in frames.iter_mut().zip(dmas.iter_mut()) { Self::free_frame(bdf, pa, dma); } return None; };
        Some((frames, dmas, data_pa, data_dma))
    }

    /// Disable the controller and return all queue/PRP frames to PMM.
    /// Existing publication must be removed and callers quiesced before this.
    /// # C: O(controller disable wait + 5 frees)
    pub fn shutdown_and_free(&mut self) {
        if self.bar0_va != 0 {
            self.w32(regs::REG_CC, 0);
            let _ = self.wait_rdy(false, 2_000);
        }
        Self::free_frame(self.bdf, &mut self.admin.sq_pa, &mut self.admin.sq_dma);
        Self::free_frame(self.bdf, &mut self.admin.cq_pa, &mut self.admin.cq_dma);
        Self::free_frame(self.bdf, &mut self.io.sq_pa, &mut self.io.sq_dma);
        Self::free_frame(self.bdf, &mut self.io.cq_pa, &mut self.io.cq_dma);
        Self::free_frame(self.bdf, &mut self.prp_list_pa, &mut self.prp_list_dma);
        if self.data_pa != 0 && iommu::unmap_dma(self.bdf, self.data_dma, (DATA_PAGES * PAGE) as usize) {
            // SAFETY: controller disable completed and this private data run has no live DMA owner.
            unsafe { pmm::setup::free_contig(self.data_pa, DATA_ORDER); }
            self.data_pa = 0;
            self.data_dma = 0;
        }
        self.bar0_va = 0;
        self.mmio.unmap();
    }

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
    pub fn bring_up(bdf: pci::Bdf, mmio: Mapping, bar0_off: u64, io_vector: u16) -> Option<Nvme> {
        // Allocate queue frames, one PRP-list page, and the serialized I/O data run.
        let ([asq, acq, isq, icq, prp_list], [asq_dma, acq_dma, isq_dma, icq_dma, prp_list_dma], data_pa, data_dma) = Self::alloc_frames(bdf)?;
        for f in [asq, acq, isq, icq, prp_list] { Self::zero_frame(f); }
        for page in 0..DATA_PAGES { Self::zero_frame(data_pa + page * PAGE); }
        let bar0_va = mmio.base_va() + bar0_off;

        // Pre-read DSTRD from CAP off `bar0_va` directly: the doorbell VAs it
        // yields are baked into the queues, so no `self` exists yet to read it.
        // SAFETY: bar0_va is the Device-attr-mapped register file; aligned
        // 32-bit loads of CAP's two halves to compute the doorbell stride.
        let cap = unsafe {
            (core::ptr::read_volatile((bar0_va + regs::REG_CAP) as *const u32) as u64)
            | ((core::ptr::read_volatile((bar0_va + regs::REG_CAP + 4) as *const u32) as u64) << 32)
        };
        let dstrd = regs::cap_dstrd(cap);
        let io_entries = regs::io_queue_entries(cap, Q_ENTRIES);

        let admin = Queue {
            sq_pa: asq, sq_dma: asq_dma, cq_pa: acq, cq_dma: acq_dma, entries: Q_ENTRIES,
            sq_tail: 0, cq_head: 0, cq_phase: true,
            sq_db_va: bar0_va + regs::doorbell_off(0, false, dstrd),
            cq_db_va: bar0_va + regs::doorbell_off(0, true,  dstrd),
            cid: 0,
        };
        let io = Queue {
            sq_pa: isq, sq_dma: isq_dma, cq_pa: icq, cq_dma: icq_dma, entries: io_entries,
            sq_tail: 0, cq_head: 0, cq_phase: true,
            sq_db_va: bar0_va + regs::doorbell_off(1, false, dstrd),
            cq_db_va: bar0_va + regs::doorbell_off(1, true,  dstrd),
            cid: 0,
        };

        let mut nv = Nvme {
            bdf, mmio, bar0_va, admin, io, data_pa, data_dma, prp_list_pa: prp_list, prp_list_dma,
            ns_blocks: 0, blk_size: 512,
        };
        let to_ms = regs::cap_to_ms(cap).max(2_000);

        // 1. Disable: CC.EN=0, wait CSTS.RDY==0.
        nv.w32(regs::REG_CC, 0);
        if !nv.wait_rdy(false, to_ms) {
            nv.shutdown_and_free();
            return None;
        }

        // 2. Program admin queue attributes + base addresses.
        nv.w32(regs::REG_AQA, regs::aqa(nv.admin.entries));
        nv.w64(regs::REG_ASQ, nv.admin.sq_dma);
        nv.w64(regs::REG_ACQ, nv.admin.cq_dma);

        // 3. Enable: CC with IOSQES/IOCQES + EN, wait CSTS.RDY==1.
        nv.w32(regs::REG_CC, regs::cc_enable());
        if !nv.wait_rdy(true, to_ms) {
            nv.shutdown_and_free();
            return None;
        }

        // 4. IDENTIFY controller (confirm the controller answers admin cmds).
        if nv.identify(regs::CNS_CONTROLLER, 0).is_none() {
            nv.shutdown_and_free();
            return None;
        }

        // 5. IDENTIFY namespace 1 → capacity (NSZE) + LBA format → block size.
        if !nv.identify_ns1() {
            nv.shutdown_and_free();
            return None;
        }

        // 6. Create the I/O completion + submission queue (qid=1).
        if !nv.create_io_cq(io_vector) {
            nv.shutdown_and_free();
            return None;
        }
        if !nv.create_io_sq() {
            nv.shutdown_and_free();
            return None;
        }

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
        // SAFETY: HHDM-mapped admin/IO SQ frame we own; `slot` is below this
        // queue's negotiated depth (at most 32), so the 16-dword command stays
        // within the frame; aligned stores publish it before the doorbell.
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
            q.sq_tail = (q.sq_tail + 1) % q.entries;
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
            let (head, phase, entries) = {
                let q = if qid_is_io { &self.io } else { &self.admin };
                (q.cq_head, q.cq_phase, q.entries)
            };
            let base = (head as usize) * 4; // 16-byte CQE = 4 dwords
            // SAFETY: HHDM-mapped CQ frame we own; `head` is below this
            // queue's negotiated depth (at most 32), so the 4-dword CQE stays
            // in the frame; aligned loads read controller-written status/CID.
            let (d2, d3) = unsafe {
                (core::ptr::read_volatile(cq.add(base + 2)),
                 core::ptr::read_volatile(cq.add(base + 3)))
            };
            let (cqe_phase, status_code, cqe_cid) = regs::cqe_decode(d2, d3);
            if cqe_phase == phase {
                // Advance head; wrap toggles the expected phase.
                let nh = (head + 1) % entries;
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
        cmd[6] = (self.data_dma & 0xFFFF_FFFF) as u32; // PRP1 low
        cmd[7] = (self.data_dma >> 32) as u32;         // PRP1 high
        cmd[10] = cns;                            // CDW10: CNS
        let status = self.submit(false, cmd)?;
        if status != 0 { return None; }
        Some(hhdm().wrapping_add(self.data_pa))
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
    fn create_io_cq(&mut self, vector: u16) -> bool {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::ADMIN_CREATE_IO_CQ as u32;
        cmd[6] = (self.io.cq_dma & 0xFFFF_FFFF) as u32;
        cmd[7] = (self.io.cq_dma >> 32) as u32;
        cmd[10] = ((self.io.entries - 1) << 16) | 1; // QSIZE (0-based) | QID=1
        cmd[11] = regs::create_io_cq_flags(vector);
        self.submit(false, cmd) == Some(0)
    }

    /// CREATE I/O SUBMISSION QUEUE (opcode 0x01) for qid=1, bound to CQ 1:
    /// PRP1 = SQ PA, CDW10 = ((size-1)<<16)|qid, CDW11 = (cqid<<16)|PC.
    /// # C: O(one admin cmd)
    fn create_io_sq(&mut self) -> bool {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::ADMIN_CREATE_IO_SQ as u32;
        cmd[6] = (self.io.sq_dma & 0xFFFF_FFFF) as u32;
        cmd[7] = (self.io.sq_dma >> 32) as u32;
        cmd[10] = ((self.io.entries - 1) << 16) | 1; // QSIZE (0-based) | QID=1
        cmd[11] = (1u32 << 16) | 0x1;            // CQID=1 | PC=1
        self.submit(false, cmd) == Some(0)
    }

    /// Max bytes one serialized request can map through its PRP data run. # C: O(1)
    pub const MAX_XFER: u64 = DATA_PAGES * PAGE;

    fn submit_io(&mut self, mut cmd: [u32; 16]) -> Option<IoPending> {
        let q = &mut self.io;
        let cid = q.cid;
        q.cid = q.cid.wrapping_add(1);
        cmd[0] = (cmd[0] & 0x0000_FFFF) | ((cid as u32) << 16);
        let h = hhdm();
        if h == 0 { return None; }
        let sq = h.wrapping_add(q.sq_pa) as *mut u32;
        // SAFETY: HHDM-mapped I/O SQ frame owned by this controller; tail is
        // bounded by queue depth and the 16 dword command stays in-frame.
        unsafe {
            let base = (q.sq_tail as usize) * 16;
            for (i, word) in cmd.iter().enumerate() {
                core::ptr::write_volatile(sq.add(base + i), *word);
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        q.sq_tail = (q.sq_tail + 1) % q.entries;
        // SAFETY: sq_db_va is the I/O SQ tail doorbell in the owned BAR0 map;
        // aligned 32-bit write publishes the command after the release fence.
        unsafe { core::ptr::write_volatile(q.sq_db_va as *mut u32, q.sq_tail); }
        Some(IoPending { cid })
    }

    /// Reap one I/O CQE after its MSI. None means no matching CQE is visible.
    /// # C: O(1)
    pub fn try_reap_io(&mut self, pending: IoPending) -> Option<u16> {
        let q = &mut self.io;
        let h = hhdm();
        if h == 0 { return Some(0xFFFF); }
        let cq = h.wrapping_add(q.cq_pa) as *const u32;
        let base = (q.cq_head as usize) * 4;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        // SAFETY: HHDM-mapped I/O CQ frame owned by this controller; head is
        // bounded by queue depth and this reads the 16-byte CQE in-frame.
        let (d2, d3) = unsafe {
            (core::ptr::read_volatile(cq.add(base + 2)), core::ptr::read_volatile(cq.add(base + 3)))
        };
        let (phase, status, cid) = regs::cqe_decode(d2, d3);
        if phase != q.cq_phase { return None; }
        let next_head = (q.cq_head + 1) % q.entries;
        q.cq_head = next_head;
        if next_head == 0 { q.cq_phase = !q.cq_phase; }
        // SAFETY: cq_db_va is the I/O CQ head doorbell in the owned BAR0 map;
        // aligned 32-bit write releases this CQE back to the controller.
        unsafe { core::ptr::write_volatile(q.cq_db_va as *mut u32, next_head); }
        if cid != pending.cid { return Some(0xFFFF); }
        Some(status)
    }

    /// Submit one READ (0x02) or WRITE (0x01) on the I/O queue for namespace 1.
    /// `slba` = starting LBA, `nlb_minus_1` = (block count − 1), data moves
    /// through the contiguous PRP data run. The caller stages writes into /
    /// copies reads out of the run around this call.
    /// # C: O(one I/O cmd)
    pub fn rw_submit(&mut self, write: bool, slba: u64, nlb_minus_1: u16) -> Option<IoPending> {
        let bytes = u64::from(nlb_minus_1).saturating_add(1).saturating_mul(u64::from(self.blk_size));
        let second = regs::prp_second(bytes)?;
        let mut cmd = [0u32; 16];
        cmd[0] = if write { regs::IO_WRITE } else { regs::IO_READ } as u32;
        cmd[1] = 1;                               // NSID = 1
        cmd[6] = (self.data_dma & 0xFFFF_FFFF) as u32; // PRP1 low
        cmd[7] = (self.data_dma >> 32) as u32;         // PRP1 high
        match second {
            regs::PrpSecond::None => {}
            regs::PrpSecond::DirectPage => {
                let prp2 = self.data_dma + PAGE;
                cmd[8] = prp2 as u32;
                cmd[9] = (prp2 >> 32) as u32;
            }
            regs::PrpSecond::List { entries } => {
                let h = hhdm();
                if h == 0 || self.prp_list_pa == 0 { return None; }
                let list = h.wrapping_add(self.prp_list_pa) as *mut u64;
                // SAFETY: this controller owns the 512-entry PRP-list page and entries never exceeds 511.
                unsafe { for index in 0..entries { core::ptr::write_volatile(list.add(index), self.data_dma + (index as u64 + 1) * PAGE); } }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                cmd[8] = self.prp_list_dma as u32;
                cmd[9] = (self.prp_list_dma >> 32) as u32;
            }
        }
        cmd[10] = (slba & 0xFFFF_FFFF) as u32;    // CDW10 SLBA low
        cmd[11] = (slba >> 32) as u32;            // CDW11 SLBA high
        cmd[12] = nlb_minus_1 as u32;             // CDW12 NLB (0-based)
        self.submit_io(cmd)
    }

    /// FLUSH (opcode 0x00) on the I/O queue for namespace 1. # C: O(one cmd)
    pub fn flush_submit(&mut self) -> Option<IoPending> {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::IO_FLUSH as u32;
        cmd[1] = 1; // NSID = 1
        self.submit_io(cmd)
    }

    /// HHDM VA of the serialized PRP data run, for staging/copying I/O payloads.
    /// # C: O(1)
    pub fn prp_va(&self) -> u64 { hhdm().wrapping_add(self.data_pa) }
}
