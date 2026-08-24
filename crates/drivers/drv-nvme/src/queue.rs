// NVMe controller bring-up + admin/IO queue mechanics (kernel-only — pure
// MMIO + HHDM, so this file is `cfg(target_os = "oxide-kernel")`; the math it
// uses lives in `regs.rs` and host-tests). Mirrors drv-virtio-blk/src/modern:
// the boot probe maps BAR0 and hands the register-file VA here; this module
// owns reset → admin queues → IDENTIFY → one I/O queue pair → READ/WRITE.
//
// One I/O queue pair. The BlockDevice owner keeps the live CID-indexed request
// records; this controller owns only SQ/CQ publication and retirement.

#![cfg(target_os = "oxide-kernel")]

use crate::regs;
use crate::platform::{hhdm, now_ns};
use mmio_map::Mapping;

mod commands;
mod dma;
mod observe;
pub(crate) use dma::IoDma;

/// Worst-case wait for an admin/IO completion. CAP.TO bounds RDY transitions;
/// this caps a genuinely-lost completion to EIO. 5 s is generous for QEMU.
const IO_TIMEOUT_NS: u64 = 5_000_000_000;
/// Bounded completion wait for one Admin Abort. It deliberately shares the
/// controller's finite command timeout instead of waiting behind a dead I/O.
const ADMIN_ABORT_TIMEOUT_NS: u64 = IO_TIMEOUT_NS;

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

/// One controller completion, identified by the CID the hardware returned.
#[derive(Clone, Copy)]
pub struct IoCompletion { pub cid: u16, pub status: u16 }

/// The NVMe controller bring-up state. Holds the BAR0 register-file VA, the
/// admin + single I/O queue, and the negotiated geometry (namespace block
/// size + capacity). Each live command owns its own PRP data resources.
pub struct Nvme {
    bdf:     pci::Bdf,
    dma_mask: u64,
    mmio:    Mapping,
    bar0_va: u64,
    admin:   Queue,
    io:      Queue,
    /// One controller-private page for synchronous admin IDENTIFY transfers.
    admin_data_pa: u64,
    admin_data_dma: u64,
    /// Active namespace selected from the controller's namespace list.
    nsid:    u32,
    /// Selected namespace geometry harvested at IDENTIFY.
    pub ns_blocks: u64,
    pub blk_size:  u32,
    /// Identify Controller VWC bit: acknowledged writes may be volatile.
    pub write_cache: bool,
    /// Identify Controller ACL plus one. The serialized timeout worker never
    /// submits more than this number of Admin Abort commands concurrently.
    abort_limit: u16,
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
    pub(crate) const fn bdf(&self) -> pci::Bdf { self.bdf }
    pub(crate) const fn dma_mask(&self) -> u64 { self.dma_mask }
    /// Active namespace ID selected during controller bring-up. # C: O(1)
    pub(crate) const fn namespace_id(&self) -> u32 { self.nsid }
    /// Maximum concurrently posted I/O commands, leaving one SQ entry empty.
    /// # C: O(1)
    pub(crate) const fn io_capacity(&self) -> usize { self.io.entries.saturating_sub(1) as usize }
    pub(crate) fn io_cq_cursor(&self) -> (u64, u32, bool) { (self.io.cq_pa, self.io.cq_head, self.io.cq_phase) }
    fn free_frame(bdf: pci::Bdf, pa: &mut u64, dma: &mut u64) {
        if *pa == 0 || !iommu::unmap_dma(bdf, *dma, PAGE as usize) {
            return;
        }
        // SAFETY: the caller owns controller teardown/quiesce. These frames
        // are the single-page queue/PRP allocations returned by alloc_raw_frame
        // during bring-up and are no longer reachable by live DMA.
        unsafe { pmm::setup::free_one_frame(*pa); }
        *pa = 0;
        *dma = 0;
    }

    fn alloc_frame(dma_mask: u64) -> Option<u64> {
        if dma_mask == u64::MAX { pmm::setup::alloc_raw_frame() }
        else { pmm::setup::alloc_raw_frame_below(dma_mask.checked_add(1)?) }
    }

    fn alloc_frames(bdf: pci::Bdf, dma_mask: u64) -> Option<([u64; 5], [u64; 5])> {
        let mut frames = [0u64; 5]; let mut dmas = [0u64; 5];
        let mut i = 0usize;
        while i < frames.len() {
            match Self::alloc_frame(dma_mask) {
                // SAFETY: on the IOMMU-mapping failure below, `pa` is the frame this
                // iteration just allocated and never stored into `frames`, so it has no
                // IOVA and no other reference — this is its only owner returning it.
                Some(pa) => match iommu::map_dma_below(bdf, pa, PAGE as usize, dma_mask) { Some(dma) => { frames[i] = pa; dmas[i] = dma; }, None => { unsafe { pmm::setup::free_one_frame(pa); } for (pa, dma) in frames.iter_mut().zip(dmas.iter_mut()) { Self::free_frame(bdf, pa, dma); } return None; } },
                None => {
                    for (pa, dma) in frames.iter_mut().zip(dmas.iter_mut()) {
                        Self::free_frame(bdf, pa, dma);
                    }
                    return None;
                }
            }
            i += 1;
        }
        Some((frames, dmas))
    }

    /// Disable the controller and return all queue/PRP frames to PMM.
    /// Existing publication must be removed and callers quiesced before this.
    /// # C: O(controller disable wait + 5 frees)
    pub fn shutdown_and_free(&mut self) {
        if self.bar0_va != 0 {
            self.w32(regs::REG_CC, 0);
            let _ = self.wait_rdy(false, 2_000);
        }
        self.free_frames();
        self.bar0_va = 0;
        self.mmio.unmap();
    }

    fn free_frames(&mut self) {
        Self::free_frame(self.bdf, &mut self.admin.sq_pa, &mut self.admin.sq_dma);
        Self::free_frame(self.bdf, &mut self.admin.cq_pa, &mut self.admin.cq_dma);
        Self::free_frame(self.bdf, &mut self.io.sq_pa, &mut self.io.sq_dma);
        Self::free_frame(self.bdf, &mut self.io.cq_pa, &mut self.io.cq_dma);
        Self::free_frame(self.bdf, &mut self.admin_data_pa, &mut self.admin_data_dma);
    }

    fn failed_bring_up(mut self) -> Mapping {
        if self.bar0_va != 0 { self.w32(regs::REG_CC, 0); let _ = self.wait_rdy(false, 2_000); }
        self.free_frames();
        self.mmio
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
    /// create the I/O queue pair. Returns the still-owned BAR mapping on failure.
    /// `bar0_va` is the HHDM-independent register-file VA from map_mmio_pages.
    /// # C: O(reset + 2 admin cmds + 2 create-queue cmds)
    pub fn bring_up(bdf: pci::Bdf, dma_mask: u64, mmio: Mapping, bar0_off: u64, io_vector: u16) -> Result<Nvme, Mapping> {
        // Queue and admin-IDENTIFY frames are controller-owned; posted I/O owns its PRPs.
        let Some(([asq, acq, isq, icq, admin_data], [asq_dma, acq_dma, isq_dma, icq_dma, admin_data_dma])) = Self::alloc_frames(bdf, dma_mask) else { return Err(mmio); };
        for f in [asq, acq, isq, icq, admin_data] { Self::zero_frame(f); }
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
            bdf, dma_mask, mmio, bar0_va, admin, io, admin_data_pa: admin_data, admin_data_dma,
            nsid: 0, ns_blocks: 0, blk_size: 512, write_cache: false, abort_limit: 1,
        };
        let to_ms = regs::cap_to_ms(cap).max(2_000);

        // 1. Disable: CC.EN=0, wait CSTS.RDY==0.
        nv.w32(regs::REG_CC, 0);
        if !nv.wait_rdy(false, to_ms) {
            return Err(observe::bring_up_failed(nv, b"disable-rdy"));
        }

        // 2. Program admin queue attributes + base addresses.
        nv.w32(regs::REG_AQA, regs::aqa(nv.admin.entries));
        nv.w64(regs::REG_ASQ, nv.admin.sq_dma);
        nv.w64(regs::REG_ACQ, nv.admin.cq_dma);

        // 3. Enable: CC with IOSQES/IOCQES + EN, wait CSTS.RDY==1.
        nv.w32(regs::REG_CC, regs::cc_enable());
        if !nv.wait_rdy(true, to_ms) {
            return Err(observe::bring_up_failed(nv, b"enable-rdy"));
        }

        // 4. IDENTIFY controller (confirm the controller answers admin cmds).
        if !nv.identify_controller() {
            return Err(observe::bring_up_failed(nv, b"identify-controller"));
        }

        // 5. Select one active namespace, then harvest its capacity and LBA format.
        if !nv.identify_active_namespace() {
            return Err(observe::bring_up_failed(nv, b"identify-namespace"));
        }

        // 6. Create the I/O completion + submission queue (qid=1).
        if !nv.create_io_cq(io_vector) {
            return Err(observe::bring_up_failed(nv, b"create-io-cq"));
        }
        if !nv.create_io_sq() {
            return Err(observe::bring_up_failed(nv, b"create-io-sq"));
        }

        Ok(nv)
    }

    /// Rebuild this controller's queues in place after a live reset. The BAR
    /// mapping and DMA frames remain owned by this controller throughout.
    /// # C: O(reset + 2 admin cmds + 2 create-queue cmds)
    pub(crate) fn reinitialize(&mut self, io_vector: u16) -> bool {
        if self.bar0_va == 0 { return false; }
        self.w32(regs::REG_CC, 0);
        if !self.wait_rdy(false, 2_000) { return false; }

        for pa in [self.admin.sq_pa, self.admin.cq_pa, self.io.sq_pa, self.io.cq_pa, self.admin_data_pa] {
            Self::zero_frame(pa);
        }
        let cap = self.r32(regs::REG_CAP) as u64 | ((self.r32(regs::REG_CAP + 4) as u64) << 32);
        let dstrd = regs::cap_dstrd(cap);
        self.admin.entries = Q_ENTRIES;
        self.admin.sq_tail = 0;
        self.admin.cq_head = 0;
        self.admin.cq_phase = true;
        self.admin.cid = 0;
        self.admin.sq_db_va = self.bar0_va + regs::doorbell_off(0, false, dstrd);
        self.admin.cq_db_va = self.bar0_va + regs::doorbell_off(0, true, dstrd);
        self.io.entries = regs::io_queue_entries(cap, Q_ENTRIES);
        self.io.sq_tail = 0;
        self.io.cq_head = 0;
        self.io.cq_phase = true;
        self.io.cid = 0;
        self.io.sq_db_va = self.bar0_va + regs::doorbell_off(1, false, dstrd);
        self.io.cq_db_va = self.bar0_va + regs::doorbell_off(1, true, dstrd);
        self.nsid = 0;
        self.ns_blocks = 0;
        self.blk_size = 512;

        self.w32(regs::REG_AQA, regs::aqa(self.admin.entries));
        self.w64(regs::REG_ASQ, self.admin.sq_dma);
        self.w64(regs::REG_ACQ, self.admin.cq_dma);
        self.w32(regs::REG_CC, regs::cc_enable());
        let to_ms = regs::cap_to_ms(cap).max(2_000);
        if !self.wait_rdy(true, to_ms) { return false; }
        if !self.identify_controller() { return false; }
        if !self.identify_active_namespace() { return false; }
        self.create_io_cq(io_vector) && self.create_io_sq()
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
    fn submit(&mut self, qid_is_io: bool, cmd: [u32; 16]) -> Option<u16> {
        self.submit_with_timeout(qid_is_io, cmd, IO_TIMEOUT_NS)
    }

    fn submit_with_timeout(&mut self, qid_is_io: bool, mut cmd: [u32; 16], timeout_ns: u64) -> Option<u16> {
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
        pmm::dma::clean_to_device(h.wrapping_add(sq_pa).wrapping_add(u64::from(slot) * 64), 64);
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

        self.poll_cq(qid_is_io, cq_pa, cq_db, h, cid, timeout_ns)
    }

    /// Current SQ tail of the selected queue (post-advance). # C: O(1)
    #[inline]
    fn sq_tail_of(&self, qid_is_io: bool) -> u32 {
        if qid_is_io { self.io.sq_tail } else { self.admin.sq_tail }
    }

    /// Poll the completion queue for the entry whose CID matches `cid` and
    /// whose phase bit matches the expected phase, then advance + ring the CQ
    /// head doorbell. Returns the status code. # C: O(poll until completion)
    fn poll_cq(&mut self, qid_is_io: bool, cq_pa: u64, cq_db: u64, h: u64, cid: u16, timeout_ns: u64) -> Option<u16> {
        let cq = h.wrapping_add(cq_pa) as *const u32;
        let deadline = now_ns().saturating_add(timeout_ns);
        loop {
            let (head, phase, entries) = {
                let q = if qid_is_io { &self.io } else { &self.admin };
                (q.cq_head, q.cq_phase, q.entries)
            };
            let base = (head as usize) * 4; // 16-byte CQE = 4 dwords
            pmm::dma::invalidate_from_device(h.wrapping_add(cq_pa).wrapping_add(u64::from(head) * 16), 16);
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
            if now_ns() >= deadline { observe::cq_timeout(qid_is_io, cid, d2, d3); return None; }
            core::hint::spin_loop();
        }
    }

    /// IDENTIFY (opcode 0x06): DMA a 4 KiB structure into the controller's
    /// admin page. `cns` selects controller (1) / namespace (0); `nsid` is the
    /// namespace id (0 for controller). Returns Some(prp_va) on success so
    /// the caller can read fields, None on failure. # C: O(one admin cmd)
    fn identify(&mut self, cns: u32, nsid: u32) -> Option<u64> {
        let mut cmd = [0u32; 16];
        cmd[0] = regs::ADMIN_IDENTIFY as u32;     // opcode (CID stamped in submit)
        cmd[1] = nsid;                            // NSID
        cmd[6] = (self.admin_data_dma & 0xFFFF_FFFF) as u32; // PRP1 low
        cmd[7] = (self.admin_data_dma >> 32) as u32;         // PRP1 high
        cmd[10] = cns;                            // CDW10: CNS
        let status = self.submit(false, cmd)?;
        if status != 0 { return None; }
        pmm::dma::invalidate_from_device(hhdm().wrapping_add(self.admin_data_pa), PAGE as usize);
        Some(hhdm().wrapping_add(self.admin_data_pa))
    }

    /// Select an active namespace then harvest NSZE (capacity in blocks) + the
    /// in-use LBA format's block size. NVMe §5.15.2.1: NSZE @ byte 0 (u64),
    /// FLBAS @ byte 26 (low 4 bits = active LBAF index), LBAF array @ byte
    /// 128 (16 × u32). # C: O(one admin cmd)
    fn identify_active_namespace(&mut self) -> bool {
        let list = match self.identify(regs::CNS_ACTIVE_NAMESPACE_LIST, 0) { Some(v) => v, None => return false };
        // SAFETY: the Identify command filled the owned 4 KiB admin page before this read.
        let bytes = unsafe { core::slice::from_raw_parts(list as *const u8, PAGE as usize) };
        let Some(nsid) = regs::first_active_namespace(bytes) else { return false; };
        let va = match self.identify(regs::CNS_NAMESPACE, nsid) { Some(v) => v, None => return false };
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
            self.nsid = nsid;
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

}
