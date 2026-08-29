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
        let gdt_bytes = self.read_gdt_bytes()?;
        let zeroed = gdt::inode_zeroed(&gdt_bytes, n, &self.sb);
        let unused = gdt::itable_unused(&gdt_bytes, n, &self.sb);
        let uninit = gdt::inode_uninit(&gdt_bytes, n, &self.sb);
        if zeroed { return Ok(false); }
        let geom = decide::TableGeometry::new(self.sb.inodes_per_group, self.sb.block_size,
                                              self.sb.inode_size);
        let Some(used_blocks) = decide::used_itable_blocks(&geom, unused, uninit) else {
            // The descriptor's own counters disagree with the group's size.
            // Refuse rather than zero a range that may hold live inodes.
            return Err(MountError::Gdt(gdt::GdtError::BadItableUnused));
        };
        let table = gdt::parse_descriptor(&gdt_bytes, n, &self.sb)?.inode_table;
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
            // SAFETY: process context, with no spinlock held.
            let _gdt_guard = unsafe { m.gdt_lock.lock() };
            let mut current = m.read_gdt_bytes()?;
            gdt::set_inode_zeroed(&mut current, n, &m.sb);
            m.persist_gdt_slot_bytes_meta(n, &current)?;
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
        let gdt_bytes = self.read_gdt_bytes()?;
        let next = decide::next_unzeroed_group(from, groups,
            |g| gdt::inode_zeroed(&gdt_bytes, g, &self.sb));
        let Some(n) = next else { return Ok(None) };
        self.init_inode_table(n)?;
        Ok(Some(n))
    }
}

#[cfg(test)]
pub(crate) mod tests;
