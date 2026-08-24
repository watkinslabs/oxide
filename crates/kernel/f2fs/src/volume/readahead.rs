//! Blocks fetched before a reader asks for them.
//!
//! Three mechanisms over three mappings, because the three hold different
//! things and are indexed differently: a file's data pages by block index, the
//! node blocks by node id, the metadata blocks by address. One mechanism over
//! one mapping could not serve all three — a node id is not a block address,
//! and the table an address resolves through decides which copy is current.
//!
//! All three are ADVISORY. None of them reports an error, none of them refuses
//! a read the caller went on to make, and none of them fetches outside the
//! window it was handed. What each one buys is requests: a resolved window
//! collapses into contiguous runs, and each run is one transfer where the
//! demand path would have issued one per block.
//!
//! Module manifest:
//! - `window`: the arithmetic — windows, runs, and which address a metadata
//!             index names. No volume, no medium.
//! - `data`:   a file's blocks and a compressed file's clusters.
//! - `node`:   a node's siblings, while their parent is in hand.
//! - `meta`:   the four kinds of metadata window.

use super::Volume;

#[path = "readahead/window.rs"]
pub mod window;
#[path = "readahead/data.rs"]
pub mod data;
#[path = "readahead/node.rs"]
pub mod node;
#[path = "readahead/meta.rs"]
pub mod meta;

pub use window::{RaMeta, MAX_RA_NODE};

impl<S: sectors::SectorSource> Volume<S> {
    /// Linux's `max_io_bytes` is a merge boundary, not a file-read limit.
    /// Keep the unit at whole filesystem blocks: every source request here is
    /// block-aligned, and zero means that no artificial boundary is applied.
    /// # C: O(1)
    pub(crate) fn io_run_blocks(&self, requested: usize) -> usize {
        if requested == 0 { return 0; }
        let limit = self.max_io_bytes as usize / crate::uapi::BLKSIZE;
        if limit == 0 { requested } else { requested.min(limit) }
    }

    /// Read a plain contiguous source run, split only at the live merge
    /// boundary. # C: O(len * BLKSIZE)
    pub(crate) fn read_source_run(&self, addr: u32, len: usize)
        -> Result<alloc::vec::Vec<u8>, syscall::errno::Errno> {
        let mut out = alloc::vec![0u8; len * crate::uapi::BLKSIZE];
        let mut at = 0;
        while at < len {
            let blocks = self.io_run_blocks(len - at);
            let end = at + blocks;
            self.source.read_sectors(
                u64::from(addr) + at as u64,
                &mut out[at * crate::uapi::BLKSIZE..end * crate::uapi::BLKSIZE])?;
            at = end;
        }
        Ok(out)
    }

    /// Current Linux merge boundary, in bytes. # C: O(1)
    pub fn max_io_bytes(&self) -> u32 { self.max_io_bytes }

    /// Set Linux's source-I/O merge boundary. Zero means unlimited. # C: O(1)
    pub fn set_max_io_bytes(&mut self, value: u32) { self.max_io_bytes = value; }
}

#[cfg(test)]
#[path = "../tests/readahead/count.rs"]
mod count;

#[cfg(test)]
#[path = "../tests/readahead/fetch.rs"]
mod fetch_tests;
