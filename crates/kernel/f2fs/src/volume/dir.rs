//! Finding a name, and listing a directory.
//!
//! A lookup does not scan. It hashes the name, and for each LEVEL up to the
//! directory's recorded depth it examines only the two-or-four blocks of the
//! one bucket that hash lands in. Missing a level entirely — stopping at the
//! first, or trusting a depth of zero — makes names that exist unfindable,
//! and the directory still lists them.
//!
//! A small directory has no blocks at all: its entries live inside its inode.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::dirent::{self, block as deblock, bucket, Layout};
use crate::hash;
use crate::limits::MAX_LOOKUP_DEPTH;
use crate::node::Inode;
use crate::uapi::{BLKSIZE, NAME_LEN};

use super::map::Mapped;
use super::Volume;

/// One entry as a listing reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: u32,
    pub file_type: u8,
}

impl<S: SectorSource> Volume<S> {
    /// The entry named `name` in the directory `inode`.
    /// # C: O(depth) blocks
    pub fn lookup(&self, inode: &Inode, ino: u32, name: &[u8])
        -> Result<DirEntry, Errno> {
        if name.is_empty() || name.len() > NAME_LEN { return Err(Errno::Enametoolong); }
        // Names in an encrypted directory are ciphertext without a key, so
        // answering from the stored bytes would report the wrong thing rather
        // than nothing.
        if inode.encrypted() { return Err(Errno::Eopnotsupp); }
        let folding = inode.casefolded() && self.casefold.is_some();
        let query = match (folding, self.casefold.as_ref()) {
            (true, Some(cf)) => Some(crate::casefold::Query::prepare(cf, name)?),
            _ => None,
        };
        // A folding directory buckets by the hash of the FOLDED name, so every
        // spelling searches the one bucket the entry is in.
        let want = match &query { Some(q) => q.hash(), None => hash::name_hash(name) };
        let matches = |h: u32, de: &[u8], use_hash: bool| -> bool {
            if use_hash && h != want { return false; }
            match &query { Some(q) => q.matches(de), None => de == name }
        };
        if inode.inline_dentry() {
            let (area, layout) = self.inline_dir(inode, ino)?;
            // One area: there is no bucket to pick, so the hash never gates.
            let hit = deblock::find_with(&area, &layout, |h, de| matches(h, de, false))
                .map_err(|_| Errno::Eio)?;
            return hit.map(into_entry).ok_or(Errno::Enoent);
        }
        let plan = match self.casefold.as_ref() {
            Some(cf) => crate::casefold::plan_for(folding, self.opts.lookup_mode, cf),
            None => crate::casefold::Plan::HashOnly,
        };
        let depth = inode.current_depth.min(MAX_LOOKUP_DEPTH);
        for pass in plan.passes() {
            let use_hash = *pass == crate::casefold::Pass::Hash;
            for level in 0..depth {
                // Without the hash there is no bucket to aim at, so the pass
                // walks the level whole — that is what makes it a rescan and
                // what finds an entry hashed under an older encoding.
                let range = if use_hash {
                    bucket::search_range(want, level, inode.dir_level)
                } else {
                    let n = bucket::dir_buckets(level, inode.dir_level);
                    let start = bucket::dir_block_index(level, inode.dir_level, 0);
                    start..start + u64::from(n) * u64::from(bucket::bucket_blocks(level))
                };
                for index in range {
                    let Some(block) = self.dir_block(inode, ino, index)? else { continue };
                    let hit = deblock::find_with(&block, &Layout::block(),
                                                 |h, de| matches(h, de, use_hash))
                        .map_err(|_| Errno::Eio)?;
                    if let Some(e) = hit { return Ok(into_entry(e)); }
                }
            }
        }
        Err(Errno::Enoent)
    }

    /// Every entry of a directory, in the order the medium holds them.
    /// # C: O(directory blocks)
    pub fn read_dir(&self, inode: &Inode, ino: u32) -> Result<Vec<DirEntry>, Errno> {
        // Listing needs no fold: the stored bytes ARE the names to report.
        if inode.encrypted() { return Err(Errno::Eopnotsupp); }
        if inode.inline_dentry() {
            let (area, layout) = self.inline_dir(inode, ino)?;
            let list = deblock::entries(&area, &layout).map_err(|_| Errno::Eio)?;
            return Ok(list.into_iter().map(into_entry).collect());
        }
        let blocks = inode.size.div_ceil(BLKSIZE as u64);
        let mut out = Vec::new();
        for index in 0..blocks {
            let Some(block) = self.dir_block(inode, ino, index)? else { continue };
            let list = deblock::entries(&block, &Layout::block()).map_err(|_| Errno::Eio)?;
            out.extend(list.into_iter().map(into_entry));
        }
        Ok(out)
    }

    /// Whether a directory holds anything beyond `.` and `..`.
    /// # C: O(directory blocks)
    pub fn dir_is_empty(&self, inode: &Inode, ino: u32) -> Result<bool, Errno> {
        Ok(self
            .read_dir(inode, ino)?
            .iter()
            .all(|e| hash::is_dot_or_dotdot(&e.name)))
    }

    /// One block of a directory's data, or `None` where the directory is
    /// sparse. # C: O(1 block)
    fn dir_block(&self, inode: &Inode, ino: u32, index: u64)
        -> Result<Option<Vec<u8>>, Errno> {
        match self.map_block(inode, ino, index)? {
            Mapped::At(addr) => Ok(Some(self.read_main_block(addr)?)),
            Mapped::Hole => Ok(None),
            Mapped::Compressed => Err(Errno::Eio),
        }
    }

    /// The inline entry area of a directory, and its layout.
    ///
    /// The area's size is whatever the inode has left after its extra
    /// attributes and its inline attribute reservation, so the layout is
    /// derived per inode rather than fixed — the same computation the format
    /// itself does, and getting it wrong shifts every record.
    /// # C: O(1 block)
    fn inline_dir(&self, inode: &Inode, ino: u32) -> Result<(Vec<u8>, Layout), Errno> {
        let n = self.read_inode_ref(ino)?.1;
        let (at, len) = inode.inline_data_span();
        let area = n.block.get(at..at + len).ok_or(Errno::Eio)?.to_vec();
        let layout = Layout::inline(len);
        if !layout.fits() { return Err(Errno::Eio); }
        Ok((area, layout))
    }
}

/// # C: O(name len)
fn into_entry(e: deblock::Entry) -> DirEntry {
    DirEntry { name: e.name, ino: e.ino, file_type: e.file_type }
}

/// Whether an entry names a directory. # C: O(1)
pub fn entry_is_dir(e: &DirEntry) -> bool { dirent::is_dir(e.file_type) }
