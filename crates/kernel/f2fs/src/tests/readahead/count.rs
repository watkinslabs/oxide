//! A medium that records every request made of it.
//!
//! Readahead does not change which BYTES are read — a test that asserted
//! contents would pass whether readahead happened or not, which is the trap
//! this whole file exists to avoid. What changes is the number and shape of
//! the REQUESTS, so the fixture records `(sector, blocks)` for each one and
//! the tests assert over that list.

use alloc::vec::Vec;

use core::cell::RefCell;

use sectors::{MemImage, SectorSource};
use syscall::errno::Errno;

use crate::uapi::BLKSIZE;

/// A medium that answers from an image and remembers what it was asked.
pub struct Counting {
    inner: MemImage,
    reqs: RefCell<Vec<(u64, usize)>>,
}

impl Counting {
    /// # C: O(1)
    pub fn new(inner: MemImage) -> Self { Self { inner, reqs: RefCell::new(Vec::new()) } }

    /// Forget every request so far — what a test calls just before the
    /// operation it is measuring, so a mount's own reads are not counted.
    /// # C: O(1)
    pub fn clear(&self) { self.reqs.borrow_mut().clear(); }

    /// Every read request, in order, as `(first block, blocks)`. # C: O(n)
    pub fn reqs(&self) -> Vec<(u64, usize)> { self.reqs.borrow().clone() }

    /// The requests that touched the block span `[first, first + len)`.
    ///
    /// A read of a file also reads its inode and its node table, so a count
    /// over every request would move whenever an unrelated cache did. The
    /// span narrows the assertion to the blocks under test.
    /// # C: O(n)
    pub fn reqs_in(&self, first: u32, len: u32) -> Vec<(u64, usize)> {
        let (lo, hi) = (u64::from(first), u64::from(first) + u64::from(len));
        self.reqs().into_iter().filter(|(s, n)| *s < hi && *s + *n as u64 > lo).collect()
    }
}

impl SectorSource for Counting {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        self.reqs.borrow_mut().push((sector, buf.len() / BLKSIZE));
        self.inner.read_sectors(sector, buf)
    }

    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        self.inner.write_sectors(sector, buf)
    }

    fn writable(&self) -> bool { self.inner.writable() }
}
