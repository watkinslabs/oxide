// What a queued direct transfer against a block device turns into: the
// alignment rules, the end-of-device rules, and the block range to issue.
//
// Kept apart from the code that issues it so the rules can be tested without a
// device: every one of them is a decision the reference makes before a bio is
// ever built, and each has a different answer a caller must be able to tell
// apart — a misaligned request is refused, a read that starts past the end is
// end-of-file, and a write that starts past the end is out of space.

use vfs::VfsError;

/// What to do with one direct transfer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plan {
    /// Nothing reaches the device; the transfer is complete with this many
    /// bytes moved. Only ever zero, which is end-of-file for a read and the
    /// caller's own zero-length request otherwise.
    Done(usize),
    /// Issue this block range. `bytes` may be SHORTER than the caller asked
    /// for, when the request ran off the end of the device.
    Io { start_block: u64, len_blocks: u32, bytes: usize },
}

/// Turn one direct request into a plan, or refuse it.
///
/// Direct I/O carries the alignment rule the page cache would otherwise hide:
/// the offset and the length must both be whole blocks, because the transfer
/// is handed to the device as a block range and there is no cached page to
/// take a partial one apart. Both are `EINVAL`, which is the reference's
/// answer and is what distinguishes a badly formed request from a device that
/// cannot serve it.
///
/// Past the end of the device the two directions differ, and the difference is
/// the reference's: a read that starts beyond the last block has nothing to
/// return and is end-of-file, while a write there has nowhere to put the bytes
/// and is `ENOSPC`. A transfer that merely RUNS OFF the end is shortened in
/// both directions rather than refused. # C: O(1)
pub fn plan(write: bool, off: u64, len: usize, bs: u32, capacity_blocks: u64)
    -> Result<Plan, VfsError>
{
    if bs == 0 { return Err(VfsError::Einval); }
    let bs64 = bs as u64;
    if off % bs64 != 0 { return Err(VfsError::Einval); }
    if len as u64 % bs64 != 0 { return Err(VfsError::Einval); }
    if len == 0 { return Ok(Plan::Done(0)); }

    let capacity_bytes = capacity_blocks.saturating_mul(bs64);
    if off >= capacity_bytes {
        return if write { Err(VfsError::Enospc) } else { Ok(Plan::Done(0)) };
    }
    let room = capacity_bytes - off;
    let bytes = core::cmp::min(len as u64, room);
    // `room` is a whole number of blocks because `off` is block-aligned and
    // the capacity is stated in blocks, so the shortened length stays aligned.
    let len_blocks = u32::try_from(bytes / bs64).map_err(|_| VfsError::Einval)?;
    if len_blocks == 0 { return Ok(Plan::Done(0)); }
    Ok(Plan::Io { start_block: off / bs64, len_blocks, bytes: bytes as usize })
}

#[cfg(test)]
#[path = "direct/tests.rs"]
mod tests;
