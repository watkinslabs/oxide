use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest};
#[cfg(not(target_os = "oxide-kernel"))]
use core::sync::atomic::Ordering;

use super::{Mount, MountError};

impl Mount {
    pub(crate) fn write_data_byte_range(&self, byte_off: u64, data: &[u8]) -> Result<(), MountError> {
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.faults.next_data_write.swap(false, Ordering::AcqRel) { return Err(MountError::BlockIo); }
        // `data=journal`: file data goes through the journal WITH the metadata
        // that references it, which is the whole difference the mode buys — a
        // crash can then never expose a block whose extent committed but whose
        // contents never reached the disk. The other two modes write the data
        // straight to its target and differ only in when.
        if self.behaviour().data.journals_data() { return self.metadata_write(byte_off, data); }
        write_byte_range(&*self.dev, byte_off, data)
    }

    /// Write one journal block, carrying this mount's `journal_ioprio=`.
    ///
    /// The priority is the point of the option: journal writeback competes with
    /// everything else the device is doing, and a mount that asked for its
    /// commits to be scheduled ahead of (or behind) ordinary file I/O gets that
    /// only if the priority rides on the REQUEST the queue chooses between.
    /// # C: O(data.len() / sector_size) I/O
    pub(crate) fn write_journal_byte_range(&self, byte_off: u64, data: &[u8])
        -> Result<(), MountError>
    {
        write_byte_range_prio(&*self.dev, byte_off, data, self.journal_request_ioprio())
    }

    /// This mount's journal I/O priority in the packed request encoding. The
    /// option names a LEVEL; the class is best-effort, the class ordinary
    /// writeback runs at. # C: O(1)
    pub(crate) fn journal_request_ioprio(&self) -> i32 {
        sched::ioprio::prio_value(sched::ioprio::CLASS_BE, self.behaviour().journal_ioprio)
    }
}

/// Write `data` to `dev` at byte offset `byte_off`. RMW for any
/// partial-block write — `data` need not be sector-multiple. A
/// block-aligned, whole-block-multiple write SKIPS the RMW read
/// (the read-back would be fully overwritten): a fresh large-file
/// write (systemd-hwdb's 13.5MB) is all full-block writes, so the
/// pre-read doubled every data op — 27k useless serialized reads.
/// Direct device write only — does NOT consult any journal scope.
/// # C: O(data.len() / sector_size) I/O (+1 RMW read only if unaligned)
pub(crate) fn write_byte_range(dev: &dyn BlockDevice, byte_off: u64, data: &[u8])
    -> Result<(), MountError>
{
    write_byte_range_prio(dev, byte_off, data, sched::ioprio::DEFAULT)
}

/// [`write_byte_range`], with an explicit I/O priority stamped on every request
/// it submits — including the read half of an unaligned read-modify-write,
/// which the write waits on and which therefore inherits the write's urgency.
/// # C: same as `write_byte_range`
pub(crate) fn write_byte_range_prio(dev: &dyn BlockDevice, byte_off: u64, data: &[u8], ioprio: i32)
    -> Result<(), MountError>
{
    let bs = dev.block_size() as u64;
    let first_blk = byte_off / bs;
    let last_byte = byte_off + data.len() as u64;
    let last_blk_excl = (last_byte + bs - 1) / bs;
    let n_blocks = (last_blk_excl - first_blk) as u32;
    // Fast path: byte_off block-aligned AND data covers whole blocks → the
    // write fully specifies every touched block, so the pre-read is dead I/O.
    if byte_off % bs == 0 && (data.len() as u64) % bs == 0 {
        let mut wreq = BlockRequest::new_write(first_blk, n_blocks, data.to_vec());
        wreq.ioprio = ioprio;
        dev.submit_sync(&mut wreq).map_err(|_| MountError::BlockIo)?;
        return Ok(());
    }
    let mut full = BlockRequest::new_read(first_blk, n_blocks, dev.block_size());
    full.ioprio = ioprio;
    dev.submit_sync(&mut full).map_err(|_| MountError::BlockIo)?;
    let inner_off = (byte_off - first_blk * bs) as usize;
    full.buffer[inner_off .. inner_off + data.len()].copy_from_slice(data);
    let mut wreq = BlockRequest::new_write(first_blk, n_blocks, full.buffer);
    wreq.ioprio = ioprio;
    dev.submit_sync(&mut wreq).map_err(|_| MountError::BlockIo)?;
    Ok(())
}

/// Read `len` bytes from `dev` starting at byte `byte_off`.
/// Translates to whole-block reads under the hood.
/// # C: O(1)
pub(super) fn read_byte_range(dev: &dyn BlockDevice, byte_off: u64, len: usize)
    -> Result<Vec<u8>, MountError>
{
    let bs = dev.block_size() as u64;
    let first_blk = byte_off / bs;
    let last_byte = byte_off + len as u64;
    let last_blk_excl = (last_byte + bs - 1) / bs;
    let n_blocks = (last_blk_excl - first_blk) as u32;
    let mut req = BlockRequest::new_read(first_blk, n_blocks, dev.block_size());
    dev.submit_sync(&mut req).map_err(|_| MountError::BlockIo)?;
    let inner_off = (byte_off - first_blk * bs) as usize;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&req.buffer[inner_off .. inner_off + len]);
    Ok(out)
}

/// Crate-public alias so submodules (`balloc`, `extent_rw`, …) can
/// call the read helper without re-implementing block-window math.
#[inline]
pub(crate) fn read_byte_range_pub(dev: &dyn BlockDevice, byte_off: u64, len: usize)
    -> Result<Vec<u8>, MountError>
{
    read_byte_range(dev, byte_off, len)
}
