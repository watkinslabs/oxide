//! NVMe I/O SQ posting and CQ retirement mechanics.

use super::*;

impl Nvme {
    fn submit_io(&mut self, mut cmd: [u32; 16]) -> Option<IoPending> {
        let q = &mut self.io;
        let cid = q.cid;
        q.cid = q.cid.wrapping_add(1);
        cmd[0] = (cmd[0] & 0x0000_FFFF) | ((cid as u32) << 16);
        let h = hhdm();
        if h == 0 { return None; }
        let sq = h.wrapping_add(q.sq_pa) as *mut u32;
        // SAFETY: HHDM-mapped I/O SQ frame owned by this controller; tail is bounded by queue depth and the 16 dword command stays in-frame.
        unsafe { let base = (q.sq_tail as usize) * 16; for (i, word) in cmd.iter().enumerate() { core::ptr::write_volatile(sq.add(base + i), *word); } }
        pmm::dma::clean_to_device(h.wrapping_add(q.sq_pa).wrapping_add(u64::from(q.sq_tail) * 64), 64);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        q.sq_tail = (q.sq_tail + 1) % q.entries;
        // SAFETY: sq_db_va is the I/O SQ tail doorbell in the owned BAR0 map; aligned 32-bit write publishes the command after the release fence.
        unsafe { core::ptr::write_volatile(q.sq_db_va as *mut u32, q.sq_tail); }
        Some(IoPending { cid })
    }

    /// Reap one phase-valid I/O CQE after an MSI. None means no CQE is visible. # C: O(1)
    pub fn reap_io(&mut self) -> Option<IoCompletion> {
        let q = &mut self.io;
        let h = hhdm();
        if h == 0 { return Some(IoCompletion { cid: u16::MAX, status: u16::MAX }); }
        let cq = h.wrapping_add(q.cq_pa) as *const u32;
        let base = (q.cq_head as usize) * 4;
        pmm::dma::invalidate_from_device(h.wrapping_add(q.cq_pa).wrapping_add(u64::from(q.cq_head) * 16), 16);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        // SAFETY: HHDM-mapped I/O CQ frame owned by this controller; head is bounded by queue depth and this reads the 16-byte CQE in-frame.
        let (d2, d3) = unsafe { (core::ptr::read_volatile(cq.add(base + 2)), core::ptr::read_volatile(cq.add(base + 3))) };
        let (phase, status, cid) = regs::cqe_decode(d2, d3);
        if phase != q.cq_phase { return None; }
        let next_head = (q.cq_head + 1) % q.entries;
        q.cq_head = next_head;
        if next_head == 0 { q.cq_phase = !q.cq_phase; }
        // SAFETY: cq_db_va is the I/O CQ head doorbell in the owned BAR0 map; aligned 32-bit write releases this CQE back to the controller.
        unsafe { core::ptr::write_volatile(q.cq_db_va as *mut u32, next_head); }
        Some(IoCompletion { cid, status })
    }

    /// Submit one READ or WRITE on I/O queue 1 through the serialized PRP run. # C: O(one I/O cmd)
    pub fn rw_submit(&mut self, write: bool, slba: u64, nlb_minus_1: u16) -> Option<IoPending> {
        let bytes = u64::from(nlb_minus_1).saturating_add(1).saturating_mul(u64::from(self.blk_size));
        let second = regs::prp_second(bytes)?;
        let mut cmd = [0u32; 16];
        cmd[0] = if write { regs::IO_WRITE } else { regs::IO_READ } as u32;
        cmd[1] = 1;
        cmd[6] = (self.data_dma & 0xFFFF_FFFF) as u32;
        cmd[7] = (self.data_dma >> 32) as u32;
        match second {
            regs::PrpSecond::None => {}
            regs::PrpSecond::DirectPage => { let prp2 = self.data_dma + PAGE; cmd[8] = prp2 as u32; cmd[9] = (prp2 >> 32) as u32; }
            regs::PrpSecond::List { entries } => {
                let h = hhdm();
                if h == 0 || self.prp_list_pa == 0 { return None; }
                let list = h.wrapping_add(self.prp_list_pa) as *mut u64;
                // SAFETY: this controller owns the 512-entry PRP-list page and entries never exceeds 511.
                unsafe { for index in 0..entries { core::ptr::write_volatile(list.add(index), self.data_dma + (index as u64 + 1) * PAGE); } }
                pmm::dma::clean_to_device(h.wrapping_add(self.prp_list_pa), entries * core::mem::size_of::<u64>());
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                cmd[8] = self.prp_list_dma as u32; cmd[9] = (self.prp_list_dma >> 32) as u32;
            }
        }
        cmd[10] = (slba & 0xFFFF_FFFF) as u32; cmd[11] = (slba >> 32) as u32; cmd[12] = nlb_minus_1 as u32;
        self.submit_io(cmd)
    }

    /// FLUSH (opcode 0x00) on I/O queue 1. # C: O(one cmd)
    pub fn flush_submit(&mut self) -> Option<IoPending> {
        let mut cmd = [0u32; 16]; cmd[0] = regs::IO_FLUSH as u32; cmd[1] = 1; self.submit_io(cmd)
    }

    /// HHDM VA of the serialized PRP data run. # C: O(1)
    pub fn prp_va(&self) -> u64 { hhdm().wrapping_add(self.data_pa) }
}
