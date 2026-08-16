//! Gathering the runs and erasing them.

use alloc::vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::ioctl::uapi::{TRIM_FILE_DISCARD, TRIM_FILE_MASK, TRIM_FILE_ZEROOUT};
use crate::uapi::BLKSIZE;
use crate::volume::Volume;

use super::span;

impl<S: SectorSource> Volume<S> {
    /// Destroy the contents of `ino`'s blocks in `[start, start+len)` by the
    /// methods `flags` names, leaving the file's shape and length untouched.
    /// # C: O(blocks in the range)
    pub fn sec_trim_file(&mut self, ino: u32, start: u64, len: u64, flags: u64)
        -> Result<(), Errno> {
        self.writable_or_err()?;
        if flags == 0 || flags & !TRIM_FILE_MASK != 0 { return Err(Errno::Einval); }
        let inode = self.read_inode(ino)?;
        let max = self.sb_max_bytes();
        let Some(s) = span::span(inode.size, start, len, max)? else { return Ok(()) };
        // An inline file's bytes are inside its inode, where there is no block
        // to erase and erasing the inode would take the file with it. Moved
        // out FIRST, so the block those bytes land in is one this erases.
        self.convert_inline(ino)?;
        // The request may name every byte the volume could hold. Walking that
        // index space one block at a time would be a walk of billions for a
        // file of three, so it stops at the last index the file has anything
        // at — past which there is nothing to erase by construction.
        let Some(last) = self.highest_block_index(ino)? else { return Ok(()) };
        let end = s.end.min(last + 1);

        // A run is consecutive in the FILE and consecutive on the MEDIUM. One
        // that is only the first is two runs: a device is told about a span of
        // its own addresses, and a gap in the middle would name blocks
        // belonging to something else.
        let mut run: Option<(u32, u64)> = None;
        for index in s.first..end {
            let addr = match self.mapped_addr(ino, index)? { Some(a) => a, None => continue };
            match run {
                Some((first, n)) if u64::from(first) + n == u64::from(addr) => {
                    run = Some((first, n + 1));
                }
                Some((first, n)) => { self.erase_run(first, n, flags)?; run = Some((addr, 1)); }
                None => run = Some((addr, 1)),
            }
        }
        if let Some((first, n)) = run { self.erase_run(first, n, flags)?; }
        Ok(())
    }

    /// Destroy `n` blocks from `first` on.
    ///
    /// Discard first, zeroing second, and the zeroing only if the discard
    /// succeeded: a caller asking for both wants the device's own erase and a
    /// known value afterwards, and writing the known value over a discard that
    /// failed would hide the failure behind bytes that look right.
    /// # C: O(n) blocks
    fn erase_run(&mut self, first: u32, n: u64, flags: u64) -> Result<(), Errno> {
        if flags & TRIM_FILE_DISCARD != 0 {
            self.source.discard_sectors(u64::from(first), n)?;
        }
        if flags & TRIM_FILE_ZEROOUT != 0 {
            let zeros = vec![0u8; BLKSIZE];
            for i in 0..n {
                let addr = u32::try_from(u64::from(first) + i).map_err(|_| Errno::Eio)?;
                self.write_block(addr, &zeros)?;
            }
        }
        Ok(())
    }

    /// The largest byte offset this volume can hold, which is what a length of
    /// "everything" resolves to. # C: O(1)
    pub(crate) fn sb_max_bytes(&self) -> u64 {
        crate::node::path::max_block(crate::uapi::DEF_ADDRS_PER_INODE)
            .saturating_mul(BLKSIZE as u64)
    }
}

#[cfg(test)]
#[path = "../tests/sectrim/run.rs"]
mod tests;
