//! A medium that records every request made of it.
//!
//! Readahead does not change which BYTES are read — a test that asserted
//! contents would pass whether readahead happened or not, which is the trap
//! this whole file exists to avoid. What changes is the number and shape of
//! the REQUESTS, so the fixture records `(sector, blocks)` for each one and
//! the tests assert over that list.

use alloc::vec;
use alloc::vec::Vec;

use core::cell::RefCell;

use sectors::{MemImage, SectorSource};
use syscall::errno::Errno;

use crate::uapi::BLKSIZE;
use crate::opts::Options;
use crate::test_image;
use crate::volume::Volume;

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

/// A segment table wider than one block makes removing its production
/// prefetch call observable: the loader must issue one two-block transfer
/// before it walks the entries. # C: O(1)
#[test]
fn a_wide_segment_table_is_prefetched_as_one_run() {
    let mut v = Volume::mount_with(Counting::new(test_image::with_root().image()),
                                   Options::defaults(), false).unwrap();
    v.sb.segment_count_main = 56;
    v.source_ref().clear();
    v.load_segments().unwrap();
    let sit = u64::from(v.sb.sit_blkaddr);
    assert_eq!(v.source_ref().reqs_in(sit as u32, 2), vec![(sit, 2)]);
}

/// A section spanning two segments must ask for both summary blocks through
/// the live GC entry point; a one-block fixture cannot falsify that wiring.
/// # C: O(1)
#[test]
fn a_multi_segment_section_prefetches_each_summary_block() {
    let mut v = Volume::mount_with(Counting::new(test_image::with_root().image()),
                                   Options::defaults(), false).unwrap();
    v.sb.segs_per_sec = 2;
    let first = crate::uapi::sum_block_addr(v.sb.ssa_blkaddr, 0);
    v.source_ref().clear();
    v.gc_section(0).unwrap();
    assert_eq!(v.source_ref().reqs_in(first, 2),
               vec![(u64::from(first), 2)]);
}
