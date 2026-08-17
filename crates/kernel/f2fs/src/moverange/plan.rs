//! The refusal ladder and the range arithmetic, over stated facts.
//!
//! Order is contract. A caller handed `EOPNOTSUPP` knows the pair of files can
//! never do this; one handed `EINVAL` knows the request was wrong and a
//! different one might work. A ladder that tested the cheap arithmetic first
//! would report the second where the first is true.

use syscall::errno::Errno;

use crate::uapi::BLKSIZE;

/// What one of the two files is, as the ladder reads it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Facts {
    pub is_reg: bool,
    pub size: u64,
    pub encrypted: bool,
    pub compressed: bool,
    pub pinned: bool,
    pub atomic: bool,
}

/// A move the ladder admitted, in the units the exchange works in.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    /// First block of the source range.
    pub src_index: u64,
    /// First block of the destination range.
    pub dst_index: u64,
    pub blocks: u64,
    /// What the destination's length must read as afterwards.
    pub dst_size: u64,
}

/// The block size every alignment rule here is stated in.
const BLK: u64 = BLKSIZE as u64;

/// The largest byte offset a signed file position can name. A caller sending
/// more has sent a negative offset, which is a request rather than a range.
const MAX_POS: u64 = i64::MAX as u64;

/// May this move proceed, and what does it come to?
///
/// `None` is a move that is admitted and comes to nothing — the same position
/// in the same file, or a length that resolves to zero. Both are successes
/// with no work, which is different from a refusal and different from a move
/// of zero blocks that still has to set a size.
/// # C: O(1)
pub fn plan(same: bool, writable: bool, src: &Facts, dst: &Facts,
            pos_in: u64, pos_out: u64, len: u64) -> Result<Option<Plan>, Errno> {
    if !writable { return Err(Errno::Erofs); }
    if !src.is_reg || !dst.is_reg { return Err(Errno::Einval); }
    // The bytes would have to be decrypted out of one file's key and back
    // into the other's, which is a copy — the one thing this does not do.
    if src.encrypted || dst.encrypted { return Err(Errno::Eopnotsupp); }
    if pos_in > MAX_POS || pos_out > MAX_POS { return Err(Errno::Einval); }

    if same {
        if pos_in == pos_out { return Ok(None); }
        // Moving a range onto itself, later in the same file, would read
        // slots the earlier part of the same pass has already cleared.
        if pos_out > pos_in && pos_out < pos_in.saturating_add(len) {
            return Err(Errno::Einval);
        }
    }

    // A compressed file's blocks only mean anything as a whole cluster, and a
    // pinned file's addresses are promised not to move. Neither can be
    // expressed as a change of addresses.
    if src.compressed || dst.compressed || src.pinned || dst.pinned {
        return Err(Errno::Eopnotsupp);
    }
    // An atomic span's blocks belong to a shadow inode until it commits, so
    // there is nothing stable to hand over.
    if src.atomic || dst.atomic { return Err(Errno::Einval); }

    let end_in = pos_in.checked_add(len).ok_or(Errno::Einval)?;
    if end_in > src.size { return Err(Errno::Einval); }

    // A length of zero means the rest of the file, and a range reaching the
    // end takes the final partial block whole — a block is the unit an
    // address names, so half of one cannot change owner.
    let olen = if len == 0 { src.size - pos_in } else { len };
    let len = if pos_in + olen == src.size { src.size.next_multiple_of(BLK) - pos_in }
              else { olen };
    if len == 0 { return Ok(None); }

    if pos_in % BLK != 0 || (pos_in + len) % BLK != 0 || pos_out % BLK != 0 {
        return Err(Errno::Einval);
    }

    // The destination grows only to what was ASKED for, never to the block
    // boundary the last one was rounded out to: the extra bytes are the
    // source's tail padding and were never part of the file.
    let grown = pos_out.checked_add(olen).ok_or(Errno::Einval)?;
    Ok(Some(Plan {
        src_index: pos_in / BLK,
        dst_index: pos_out / BLK,
        blocks: len / BLK,
        dst_size: if grown > dst.size { grown } else { dst.size },
    }))
}

#[cfg(test)]
#[path = "../tests/moverange/plan.rs"]
mod tests;
