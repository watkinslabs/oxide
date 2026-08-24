//! What an open atomic-write span carries.
//!
//! None of it is on the medium, and that is the promise: a crash mid-span
//! leaves a file whose inode was never rewritten and a COW inode the orphan
//! list reclaims. The only durable trace of an interrupted span is the space
//! its blocks took, which the next mount hands back.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::Volume;

/// One file between START and COMMIT.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AtomicFile {
    /// The nameless inode collecting the span's blocks.
    pub cow_ino: u32,
    /// The size the file had when the span opened, restored if it is aborted.
    pub original_size: u64,
    /// The span replaces the file's contents rather than overwriting parts of
    /// them: every block the span did not write becomes a hole at commit.
    pub replace: bool,
    /// The blocks have been moved across and only durability is outstanding.
    pub committed: bool,
    /// Something was written since the span opened.
    pub dirtied: bool,
    /// Blocks written into the COW inode, which is what the volume counts
    /// as committed or revoked when the span ends.
    pub write_cnt: u64,
}

impl AtomicFile {
    /// A span just opened over a file of `size`. # C: O(1)
    pub fn new(cow_ino: u32, size: u64, replace: bool) -> Self {
        Self { cow_ino, original_size: size, replace, committed: false, dirtied: false,
               write_cnt: 0 }
    }
}

impl<S: SectorSource> Volume<S> {
    /// Whether `ino` is inside an open span. # C: O(log spans)
    pub fn is_atomic_file(&self, ino: u32) -> bool { self.atomic.contains_key(&ino) }

    /// Whether `ino` is the COW inode of an open span. # C: O(spans)
    pub fn is_cow_file(&self, ino: u32) -> bool {
        self.atomic.values().any(|a| a.cow_ino == ino)
    }

    /// The COW inode collecting `ino`'s span, when one is open.
    /// # C: O(log spans)
    pub fn atomic_cow_ino(&self, ino: u32) -> Option<u32> {
        self.atomic.get(&ino).map(|a| a.cow_ino)
    }

    /// Whether the open span replaces the file's contents. # C: O(log spans)
    pub fn atomic_is_replace(&self, ino: u32) -> bool {
        self.atomic.get(&ino).is_some_and(|a| a.replace)
    }

    /// The span's record, or `EINVAL` when nothing is open. # C: O(log spans)
    pub(crate) fn atomic_entry(&self, ino: u32) -> Result<AtomicFile, Errno> {
        self.atomic.get(&ino).copied().ok_or(Errno::Einval)
    }

    /// Blocks written into the span so far. # C: O(log spans)
    pub fn atomic_write_count(&self, ino: u32) -> u64 {
        self.atomic.get(&ino).map(|a| a.write_cnt).unwrap_or(0)
    }

    /// Highest simultaneous count of atomic-write operations. # C: O(1)
    pub fn peak_atomic_write(&self) -> u64 { self.peak_atomic_write }

    /// Reset the Linux writable peak counter. # C: O(1)
    pub fn reset_peak_atomic_write(&mut self) { self.peak_atomic_write = 0; }

    /// Files with a span open, in inode order. # C: O(spans)
    pub fn atomic_files(&self) -> alloc::vec::Vec<u32> {
        self.atomic.keys().copied().collect()
    }
}
