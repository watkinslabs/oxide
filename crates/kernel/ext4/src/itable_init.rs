// `init_itable=` — lazy inode-table initialisation.
//
// A filesystem made with lazy initialisation leaves most groups' inode tables
// as whatever was on the disk before: mkfs marks each group's descriptor as
// not-yet-zeroed and leaves the writing to the kernel. Until somebody does it,
// the tables hold garbage that a filesystem check reads as inodes, so the
// option is not a tuning knob — a mount that never honours it leaves the
// filesystem permanently unfit for a check.
//
// The reference gives this its own thread, waking per group and pausing for a
// multiple of how long the previous group took so the zeroing never competes
// with real work. There is no such thread here, so the same pacing rides the
// periodic filesystem timer, which is the only other thing in this filesystem
// that runs on its own.
//
// Module manifest:
// - decide: which group is next, how much of its table is live, and how long
//   to wait afterwards — all with no device behind them.

pub mod decide;

use crate::gdt;
use crate::mount::{Mount, MountError};

use alloc::vec;

impl Mount {
    /// Zero the never-used tail of group `n`'s inode table and record that it
    /// is now zeroed. `Ok(false)` when the group needed nothing.
    ///
    /// The zeros go STRAIGHT to the device rather than through the journal:
    /// they replace bytes that no inode owns, so there is nothing for a replay
    /// to restore and nothing a crash mid-way can corrupt — a half-zeroed table
    /// is exactly as valid as an unzeroed one, and the descriptor flag that
    /// says the work finished is the only part that is journalled.
    /// # C: O(itable bytes) I/O
    pub fn init_inode_table(&self, n: u32) -> Result<bool, MountError> {
        let (zeroed, unused, uninit) = {
            let s = self.state.lock();
            (gdt::inode_zeroed(&s.gdt_buf, n, &self.sb),
             gdt::itable_unused(&s.gdt_buf, n, &self.sb),
             gdt::inode_uninit(&s.gdt_buf, n, &self.sb))
        };
        if zeroed { return Ok(false); }
        let geom = decide::TableGeometry::new(self.sb.inodes_per_group, self.sb.block_size,
                                              self.sb.inode_size);
        let Some(used_blocks) = decide::used_itable_blocks(&geom, unused, uninit) else {
            // The descriptor's own counters disagree with the group's size.
            // Refuse rather than zero a range that may hold live inodes.
            return Err(MountError::Gdt(gdt::GdtError::BadItableUnused));
        };
        let table = {
            let s = self.state.lock();
            gdt::parse_descriptor(&s.gdt_buf, n, &self.sb)?.inode_table
        };
        let bs = self.sb.block_size as u64;
        let to_zero = geom.blocks_per_table.saturating_sub(used_blocks);
        if to_zero != 0 {
            let start = table.saturating_add(used_blocks as u64);
            let zeros = vec![0u8; (to_zero as u64 * bs) as usize];
            crate::mount::io_write_byte_range(&*self.dev, start * bs, &zeros)?;
            // `barrier`: the flag below says the zeros are on the disk, so it
            // must not overtake them on a device that reorders.
            if self.behaviour().barrier { let _ = self.dev.flush(); }
        }
        self.run_journaled(|m| {
            { let mut s = m.state.lock(); gdt::set_inode_zeroed(&mut s.gdt_buf, n, &m.sb); }
            m.persist_gdt_slot_meta(n)?;
            m.flush_pending_tx()
        })?;
        Ok(true)
    }

    /// Zero the inode table of the first group at or after `from` that still
    /// needs it, and answer which group that was. `None` when every group from
    /// there on is already done.
    /// # C: O(N_groups) + O(itable bytes) I/O
    pub fn init_next_inode_table(&self, from: u32) -> Result<Option<u32>, MountError> {
        let groups = self.sb.group_count();
        let next = {
            let s = self.state.lock();
            decide::next_unzeroed_group(from, groups,
                |g| gdt::inode_zeroed(&s.gdt_buf, g, &self.sb))
        };
        let Some(n) = next else { return Ok(None) };
        self.init_inode_table(n)?;
        Ok(Some(n))
    }
}

#[cfg(test)]
pub(crate) mod tests;
