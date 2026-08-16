//! One cached run, which of the two caches it belongs to, and what makes two
//! of them one.
//!
//! The two caches answer different questions over the same shape. The READ
//! cache maps a file offset to a block address, so two runs are one run when
//! they are contiguous in BOTH the file and the volume. The AGE cache maps a
//! file offset to how long ago its block was written, so two runs are one run
//! when they are contiguous in the file and their ages are close enough that
//! separating them would say more than the measurement supports.

use super::limits::{F2FS_EXTENT_AGE_INVALID, SAME_AGE_REGION};

/// Which cache an entry belongs to.
///
/// The discriminants are the positions the mount's own hit counters use, so
/// one index serves both structures and neither can drift from the other.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// File offset to block address.
    Read = 0,
    /// File offset to how long ago the block was written.
    BlockAge = 1,
}

impl Kind {
    /// # C: O(1)
    pub fn index(self) -> usize { self as usize }
    /// Both kinds, in index order. # C: O(1)
    pub const ALL: [Kind; 2] = [Kind::Read, Kind::BlockAge];
}

/// One run of a file, as one of the caches holds it.
///
/// The last two fields belong to the age cache and the third to the read
/// cache; an entry carries both halves rather than a union because the cost is
/// two words and the alternative is a shape whose meaning depends on where it
/// is stored.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Info {
    /// First file block the run covers.
    pub fofs: u32,
    /// Blocks the run covers.
    pub len: u32,
    /// Volume address of the run's first block.
    pub blk: u32,
    /// Blocks allocated volume-wide between the run being written and last
    /// being looked at — the run's age.
    pub age: u64,
    /// The volume-wide allocation count the age was last measured against.
    pub last_blocks: u64,
}

impl Info {
    /// A read-cache run. # C: O(1)
    pub fn read(fofs: u32, len: u32, blk: u32) -> Info {
        Info { fofs, len, blk, age: 0, last_blocks: 0 }
    }

    /// An age-cache run. # C: O(1)
    pub fn aged(fofs: u32, len: u32, age: u64, last_blocks: u64) -> Info {
        Info { fofs, len, blk: 0, age, last_blocks }
    }

    /// An age-cache range update that carries no age: invalidate only. # C: O(1)
    pub fn invalidate(fofs: u32, len: u32) -> Info {
        Info { fofs, len, blk: 0, age: 0, last_blocks: F2FS_EXTENT_AGE_INVALID }
    }

    /// One past the last file block the run covers. # C: O(1)
    pub fn end(&self) -> u32 { self.fofs + self.len }

    /// Whether the run answers for file block `fofs`. # C: O(1)
    pub fn covers(&self, fofs: u32) -> bool { self.fofs <= fofs && fofs < self.end() }

    /// The volume address the run gives block `fofs`, when it covers it.
    /// # C: O(1)
    pub fn block(&self, fofs: u32) -> Option<u32> {
        if self.covers(fofs) { Some(self.blk + (fofs - self.fofs)) } else { None }
    }
}

/// Rewrite a run's fields for `kind`, leaving the other kind's alone.
///
/// Only the fields the named cache answers from are touched: an age entry
/// re-based by a split keeps its block field untouched because nothing reads
/// it, and a read entry keeps its age fields for the same reason.
/// # C: O(1)
pub fn set_info(ei: &mut Info, fofs: u32, len: u32, blk: u32,
                age: u64, last_blocks: u64, kind: Kind) {
    ei.fofs = fofs;
    ei.len = len;
    match kind {
        Kind::Read => ei.blk = blk,
        Kind::BlockAge => { ei.age = age; ei.last_blocks = last_blocks; }
    }
}

/// Whether `front` continues `back` closely enough to be the same run.
///
/// For the read cache both the file offsets and the volume addresses must
/// meet: two runs adjacent in the file but scattered on the volume are two
/// runs, and merging them would hand out an address the file does not own.
/// # C: O(1)
pub fn mergeable(back: &Info, front: &Info, kind: Kind) -> bool {
    if back.end() != front.fofs { return false; }
    match kind {
        Kind::Read => back.blk + back.len == front.blk,
        Kind::BlockAge => {
            back.age.abs_diff(front.age) <= SAME_AGE_REGION
                && back.last_blocks.abs_diff(front.last_blocks) <= SAME_AGE_REGION
        }
    }
}

/// Which structure answered a lookup.
///
/// The three are reported separately because they cost differently and a
/// mount whose answers come from the last one is a mount whose cache is not
/// doing the job the first two exist for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Hit {
    /// The single longest run the inode's tree has ever held.
    Largest,
    /// The one run the tree remembers being asked for last.
    Cached,
    /// The ordered tree itself.
    Tree,
}

/// What a lookup found, and whether anything was looked at.
///
/// `NoTree` and `Miss` are kept apart because the mount counts them
/// differently: a lookup against an inode with no cache is not a cache miss,
/// and counting it as one would make the hit ratio a function of how many
/// inodes are uncacheable.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Lookup {
    /// This inode has no tree of this kind; nothing was consulted.
    NoTree,
    /// A tree was consulted and did not cover the offset.
    Miss,
    /// A tree answered, from the structure named.
    Found(Info, Hit),
}

impl Lookup {
    /// Whether a tree was consulted, which is what makes the lookup countable.
    /// # C: O(1)
    pub fn consulted(&self) -> bool { !matches!(self, Lookup::NoTree) }

    /// The run and the structure that gave it. # C: O(1)
    pub fn found(&self) -> Option<(Info, Hit)> {
        match self { Lookup::Found(ei, h) => Some((*ei, *h)), _ => None }
    }

    /// The volume address for `fofs`, when the read cache answered. # C: O(1)
    pub fn block(&self, fofs: u32) -> Option<(u32, Hit)> {
        match self { Lookup::Found(ei, h) => ei.block(fofs).map(|b| (b, *h)), _ => None }
    }
}

/// What an inode is, as far as the caches are concerned.
///
/// Nothing here knows what an inode is; the caller states the four facts that
/// decide whether an inode may be cached, so the decision is checkable without
/// one.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Gate {
    pub is_reg: bool,
    pub is_dir: bool,
    /// Contents are stored compressed, so a file offset does not name a block.
    pub compressed: bool,
    /// The file is marked cold, so its age carries no information.
    pub cold: bool,
    /// The volume's own features permit reads only, which is the one case a
    /// compressed file may still be read-cached: nothing will rewrite it.
    pub readonly_volume: bool,
}

impl Gate {
    /// An ordinary file. # C: O(1)
    pub fn regular() -> Gate { Gate { is_reg: true, ..Gate::default() } }
    /// A directory. # C: O(1)
    pub fn directory() -> Gate { Gate { is_dir: true, ..Gate::default() } }
}

#[cfg(test)]
#[path = "../tests/extcache/info.rs"]
mod tests;
