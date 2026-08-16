//! Attesting a verity file's data against the tree stored past it.
//!
//! Clamping reads to the data size stops the hash tree being served AS data.
//! It says nothing about whether the data is the data that was sealed. That is
//! this file: every block a verity file returns is hashed and walked up to the
//! root before the bytes reach the caller.
//!
//! The tree lives PAST the file's size, so it cannot be read through the
//! ordinary path — which clamps, by design. It is read through the block map
//! directly, which is the one place in this filesystem allowed to look past a
//! file's own length.
//!
//! What is NOT here is the metadata walk. Locating and parsing the descriptor
//! costs an index walk, a read past the end and a parse; doing it per block
//! made the metadata cost scale with the data. It happens once per inode and
//! lives in `verity::info`, and so does the record of which hash blocks are
//! already known good.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::Inode;
use crate::uapi::BLKSIZE;
use crate::verity::info::Info;
use crate::verity::{self, walk};

use super::map::Mapped;
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Install the certificates a built-in signature must reach, and whether
    /// an unsigned verity file may be read.
    ///
    /// Whatever was held for already-opened files goes with it: an entry was
    /// admitted under the OLD policy, and leaving it would let a file that
    /// the new policy refuses keep being read.
    /// # C: O(cached inodes)
    pub fn set_verity_policy(&mut self, policy: verity::Policy) {
        self.verity_policy = policy;
        self.verity_cache.borrow_mut().clear();
    }

    /// What this mount will accept from a built-in signature. # C: O(1)
    pub fn verity_policy(&self) -> &verity::Policy { &self.verity_policy }

    /// Read this inode's verity metadata from the medium and make an `Info`
    /// of it.
    ///
    /// Everything is checked against the inode's OWN size: the size is what
    /// separates the data from the metadata, so a descriptor built over a
    /// different length describes a different file and is refused rather than
    /// used to attest this one. The built-in signature, if the descriptor
    /// carries one, is checked as part of this.
    /// # C: O(descriptor bytes + chain)
    pub(crate) fn verity_info(&self, inode: &Inode, ino: u32) -> Result<Info, Errno> {
        let attr = self.verity_attr(inode, ino)?;
        // The attribute names where the descriptor sits and how long it is;
        // the descriptor is not at a fixed place, so it is located before it
        // is read rather than read from a guessed offset.
        let loc = verity::location::parse(&attr).map_err(|e| e.errno())?;
        let ceiling = crate::node::path::max_block(inode.addrs_per_inode()) * BLKSIZE as u64;
        verity::location::check(&loc, inode.size, ceiling).map_err(|e| e.errno())?;
        let desc = self.read_past_end(inode, ino, loc.pos, loc.size as usize)?;
        let v = verity::resolve(&attr, &desc, inode.size, ceiling).map_err(|e| e.errno())?;
        Info::open(&v.descriptor, &v.signature, inode.size, &self.verity_policy)
            .map_err(|e| e.errno())
    }

    /// Read bytes a verity file's own length does not cover.
    ///
    /// The ordinary reader clamps to the size and must: for every other file
    /// the blocks past it are padding. A verity file is the one case where
    /// they are meaningful, so this reads through the map instead.
    /// # C: O(bytes)
    pub(crate) fn read_past_end(&self, inode: &Inode, ino: u32, off: u64, len: usize)
        -> Result<Vec<u8>, Errno> {
        let mut out = vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let pos = off + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(len - done);
            match self.map_block(inode, ino, index)? {
                Mapped::At(addr) => {
                    let block = self.read_main_block(addr)?;
                    out[done..done + take].copy_from_slice(&block[skew..skew + take]);
                }
                // A hole in the metadata is not padding: the tree is written
                // whole, so a missing block means the metadata is not there.
                Mapped::Hole => return Err(Errno::Eio),
                Mapped::Compressed => return Err(Errno::Eio),
            }
            done += take;
        }
        Ok(out)
    }

    /// Whether the file block at `index` holds the bytes the tree attests to.
    ///
    /// The tree's block size may be SMALLER than the filesystem's, so one
    /// file block can carry several attested blocks; each is checked in turn.
    /// A tree block wholly past the data is covered by no hash and is
    /// required to be zero instead — the tail of the last file block is
    /// visible to a caller that maps it, so leaving it unchecked would leave
    /// bytes a reader can see and the tree never saw.
    /// # C: O(blocks per file block * levels)
    pub(crate) fn verity_check(&self, inode: &Inode, ino: u32, index: u64, data: &[u8])
        -> Result<bool, Errno> {
        // The descriptor is read and parsed at most once per inode. Building
        // it needs the medium, so it happens BEFORE the cache is borrowed:
        // nothing below reaches back into the cache, and keeping the two
        // apart is what makes that true by construction rather than by
        // inspection.
        let fresh = match self.verity_cache.borrow_mut().get(ino, inode.size) {
            Some(_) => None,
            None => Some(self.verity_info(inode, ino)?),
        };
        let mut cache = self.verity_cache.borrow_mut();
        let info = match fresh {
            Some(i) => cache.insert(ino, i),
            None => cache.get(ino, inode.size).expect("present, and for this file"),
        };
        let per = BLKSIZE / info.params.block_size;
        for sub in 0..per {
            let bidx = index * per as u64 + sub as u64;
            let at = sub * info.params.block_size;
            let one = &data[at..at + info.params.block_size];
            if !self.verity_one(inode, ino, info, bidx, one)? { return Ok(false); }
        }
        Ok(true)
    }

    /// One attested block against the tree. # C: O(levels)
    fn verity_one(&self, inode: &Inode, ino: u32, info: &mut Info, index: u64, data: &[u8])
        -> Result<bool, Errno> {
        // Split the borrow: the walk reads the geometry and the root while it
        // writes the verified map, and all three are fields of one record.
        let Info { params, root_hash, verified, .. } = info;
        // A file of one block or less has no tree: its own hash is the root,
        // and there is nothing above it to have been cached.
        if verity::merkle::is_flat(params) {
            if (index << params.log_blocksize) >= params.data_size {
                return Ok(data.iter().all(|&b| b == 0));
            }
            return Ok(params.hash_block(data).map_err(|e| e.errno())?.as_bytes() == root_hash);
        }
        let tree_at = verity::metadata_pos(inode.size);
        let block_size = params.block_size;
        let mut err: Option<Errno> = None;
        let ok = walk::verify_block(
            params, root_hash, verified, index, data,
            |tree_block| {
                let at = tree_at + tree_block * block_size as u64;
                match self.read_past_end(inode, ino, at, block_size) {
                    Ok(b) => Ok(b),
                    Err(e) => { err = Some(e); Err(verity::VerityError::Corrupted) }
                }
            },
        );
        if let Some(e) = err { return Err(e); }
        ok.map_err(|e| e.errno())
    }
}

#[cfg(test)]
#[path = "../tests/veritysealed.rs"]
mod tests;
