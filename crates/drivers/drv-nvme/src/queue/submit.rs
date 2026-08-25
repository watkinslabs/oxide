use super::*;

impl Nvme {
    /// Poll CSTS.RDY until it equals `want`, bounded by `to_ms`. Fails on
    /// CSTS.CFS (controller fatal). # C: O(poll until RDY flips)
    pub(super) fn wait_rdy(&self, want: bool, to_ms: u64) -> bool {
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
    pub(super) fn submit(&mut self, qid_is_io: bool, cmd: [u32; 16]) -> Option<u16> {
        self.submit_with_timeout(qid_is_io, cmd, IO_TIMEOUT_NS)
    }

    pub(super) fn submit_with_timeout(&mut self, qid_is_io: bool, mut cmd: [u32; 16], timeout_ns: u64) -> Option<u16> {
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

}

