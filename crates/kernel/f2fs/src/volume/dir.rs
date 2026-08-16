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
        // An encrypted directory stores ciphertext. With the key the query is
        // encrypted and compared as ciphertext; without it the query IS a
        // no-key name, which carries the hash the entry was filed under.
        let crypt = self.crypt_info(inode, ino)?;
        let search = if inode.encrypted() {
            Some(crate::crypto::setup(crypt.as_ref(), name, true).map_err(|e| e.errno())?)
        } else { None };
        // A locked directory cannot fold: the caller's name is a record, not
        // a spelling of anything.
        let locked = inode.encrypted() && crypt.is_none();
        let folding = inode.casefolded() && self.casefold.is_some() && !locked;
        let query = match (folding, self.casefold.as_ref()) {
            (true, Some(cf)) => Some(crate::casefold::Query::prepare(cf, name)?),
            _ => None,
        };
        // A folding directory buckets by the hash of the FOLDED name, so every
        // spelling searches the one bucket the entry is in. When it also
        // encrypts, that hash is a KEYED hash of the folded plaintext: the
        // stored ciphertext differs per spelling, so hashing it would file two
        // spellings of one name in two buckets.
        let want = match (&crypt, &query, &search) {
            (Some(c), Some(q), _) if c.has_dirhash_key() => {
                let folded =
                    if q.kind() == crate::casefold::Fold::Folded { q.folded() } else { name };
                c.dirhash(folded).unwrap_or_else(|| hash::name_hash(folded))
            }
            (_, _, Some(s)) => match s.hash() {
                Some(h) => h,
                None => hash::name_hash(s.disk_name().unwrap_or(name)),
            },
            (_, Some(q), None) => q.hash(),
            _ => hash::name_hash(name),
        };
        let matches = |h: u32, de: &[u8], use_hash: bool| -> bool {
            if use_hash && h != want { return false; }
            match (&crypt, &query, &search) {
                // Folding over ciphertext is meaningless, so the stored name
                // is decrypted before it is folded.
                (Some(c), Some(q), _) =>
                    c.decrypt_name(de).map(|p| q.matches(&p)).unwrap_or(false),
                (_, _, Some(s)) => s.matches(de),
                (_, Some(q), None) => q.matches(de),
                _ => de == name,
            }
        };
        if inode.inline_dentry() {
            let (area, layout) = self.inline_dir(inode, ino)?;
            // One area: there is no bucket to pick, so the hash never gates.
            let hit = deblock::find_with(&area, &layout, |h, de| matches(h, de, false))
                .map_err(|_| Errno::Eio)?;
            return hit.map(|e| self.present_entry(&crypt, inode, e))
                .transpose()?
                .ok_or(Errno::Enoent);
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
                    if let Some(e) = hit { return self.present_entry(&crypt, inode, e); }
                }
            }
        }
        Err(Errno::Enoent)
    }

    /// Every entry of a directory, in the order the medium holds them.
    /// # C: O(directory blocks)
    pub fn read_dir(&self, inode: &Inode, ino: u32) -> Result<Vec<DirEntry>, Errno> {
        // Listing needs no fold: the stored bytes ARE the names to report.
        // An encrypted directory is the exception — with the key its names are
        // decrypted, and without it they are presented as the encoded records
        // a later lookup decodes back.
        let crypt = self.crypt_info(inode, ino)?;
        if inode.inline_dentry() {
            let (area, layout) = self.inline_dir(inode, ino)?;
            let list = deblock::entries(&area, &layout).map_err(|_| Errno::Eio)?;
            return list.into_iter().map(|e| self.present_entry(&crypt, inode, e)).collect();
        }
        let blocks = inode.size.div_ceil(BLKSIZE as u64);
        let mut out = Vec::new();
        for index in 0..blocks {
            let Some(block) = self.dir_block(inode, ino, index)? else { continue };
            let list = deblock::entries(&block, &Layout::block()).map_err(|_| Errno::Eio)?;
            for e in list { out.push(self.present_entry(&crypt, inode, e)?); }
        }
        Ok(out)
    }

    /// One stored entry as a caller sees it: the name decrypted where the key
    /// allows, encoded where it does not, and unchanged where the directory
    /// does not encrypt at all.
    /// # C: O(name len)
    fn present_entry(&self, crypt: &Option<crate::crypto::Info>, inode: &Inode,
                     e: deblock::Entry) -> Result<DirEntry, Errno> {
        if !inode.encrypted() { return Ok(into_entry(e)); }
        let name = crate::crypto::present(crypt.as_ref(), e.hash, &e.name)
            .map_err(|err| err.errno())?;
        Ok(DirEntry { name, ino: e.ino, file_type: e.file_type })
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
