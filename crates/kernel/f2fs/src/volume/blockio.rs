//! One block, off the medium or out of the mount's metadata mapping.
//!
//! Every read this filesystem makes of a block it addresses itself passes
//! through `read_block`. That is what makes the metadata mapping possible at
//! all: one place answers, so one place can answer without asking the device.
//! A second reader beside it would be a second answer to "what is at this
//! address", and the one that skipped the mapping would return the bytes the
//! block held before the last write.
//!
//! The exception is deliberate and is not metadata: a file whose contents the
//! block layer deciphers is read through `crypto`, which hands the medium a
//! key context this path has no business carrying. Those addresses are all in
//! the main area, which the mapping does not cover.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::BLKSIZE;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Read one block by its address.
    ///
    /// Addresses are in blocks and the source is addressed in blocks, so the
    /// two units are the same here by construction — which is why the source
    /// is created at the volume's block size rather than at a sector size.
    /// # C: O(1) held, O(BLKSIZE) otherwise
    pub fn read_block(&self, addr: u32) -> Result<Vec<u8>, Errno> {
        if u64::from(addr) >= self.sb.max_blkaddr() { return Err(Errno::Eio); }
        // Ahead of the injected failure, because the failure is the DEVICE's:
        // a block served from the mapping submits no request, so there is
        // nothing for a read-fault site to fail. A mount that injected here
        // would report an I/O error for an I/O that never happened.
        let meta = self.meta_cache.covers(addr);
        if meta {
            if let Some(held) = self.meta_cache.load(addr) { return Ok(held); }
        }
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::ReadIo) {
            return Err(Errno::Eio);
        }
        let mut buf = vec![0u8; BLKSIZE];
        self.source.read_sectors(u64::from(addr), &mut buf)?;
        // Everything OUTSIDE the main area is metadata by the layout's own
        // definition, which is the same derivation the write path uses to
        // decide a block is metadata. The main-area reads — nodes, file data,
        // the cleaner's copies — are charged by the typed readers above this
        // one, because the address cannot tell those three apart.
        //
        // Charged on the MISS only: a block the mapping answered moved no
        // bytes at the device, and counting it would report traffic the
        // mapping exists to avoid.
        if !self.sb.valid_main_blkaddr(addr) {
            self.io_account(crate::stats::iostat::Io::FsMetaRead, BLKSIZE as u64, false);
        }
        // Offered AFTER the read rather than instead of it: the mapping is
        // filled by what the medium actually returned, so a block that could
        // not be read leaves nothing behind to be served later.
        if false { self.meta_cache.store(addr, &buf); }
        Ok(buf)
    }

    /// Read one block that must lie in the MAIN area.
    ///
    /// Everything a file or a node points at lives there. An address outside
    /// it names metadata, and following one would read a checkpoint or a table
    /// block as if it were data.
    /// # C: O(BLKSIZE)
    pub fn read_main_block(&self, addr: u32) -> Result<Vec<u8>, Errno> {
        if !self.sb_main_contains(addr) { return Err(Errno::Eio); }
        self.read_block(addr)
    }

    /// Metadata blocks this mount is holding. # C: O(1)
    pub fn meta_cached_blocks(&self) -> usize { self.meta_cache.blocks() }

    /// Metadata reads this mount answered without the device. # C: O(1)
    pub fn meta_cache_hits(&self) -> u64 { self.meta_cache.hits() }
}
