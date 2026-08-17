//! Which bytes a request names, and whether they are nameable at all.
//!
//! The one asymmetry is the tail. A request that reaches the end of the file
//! is allowed to end mid-block, because the file itself does — its last block
//! is on the medium whole, and erasing it whole destroys only bytes past the
//! length. A request that stops SHORT of the end may not: erasing the rest of
//! a block whose front half the caller wants to keep would destroy data
//! nobody asked about.

use syscall::errno::Errno;

use crate::uapi::BLKSIZE;

/// The blocks a request comes to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Span {
    /// First block of the file to erase.
    pub first: u64,
    /// One past the last.
    pub end: u64,
}

const BLK: u64 = BLKSIZE as u64;

/// The blocks `[start, start+len)` of a file of `size` bytes comes to, bounded
/// by `max_bytes` for the length that means "everything".
///
/// `None` is a request that names nothing and is a success: a length of zero
/// erases nothing, which is different from a request that cannot be expressed.
/// # C: O(1)
pub fn span(size: u64, start: u64, len: u64, max_bytes: u64) -> Result<Option<Span>, Errno> {
    if start >= size { return Err(Errno::Einval); }
    if len == 0 { return Ok(None); }
    // Whether the request stops inside the file decides both where it ends and
    // whether its end has to be aligned.
    let (end_addr, to_end) = if size - start > len {
        (start + len, false)
    } else if len == u64::MAX {
        (max_bytes, true)
    } else {
        (size, true)
    };
    if start % BLK != 0 || (!to_end && end_addr % BLK != 0) { return Err(Errno::Einval); }
    Ok(Some(Span { first: start / BLK, end: end_addr.div_ceil(BLK) }))
}

#[cfg(test)]
#[path = "../tests/sectrim/span.rs"]
mod tests;
