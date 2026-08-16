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

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::Inode;
use crate::uapi::BLKSIZE;
use crate::verity::{self, merkle};

use super::map::Mapped;
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// The tree geometry and root hash for a verity inode.
    ///
    /// Everything is checked against the inode's OWN size: the size is what
    /// separates the data from the metadata, so a descriptor built over a
    /// different length describes a different file and is refused rather than
    /// used to attest this one.
    /// # C: O(descriptor bytes)
    pub(crate) fn verity_params(&self, inode: &Inode, ino: u32)
        -> Result<(merkle::Params, Vec<u8>), Errno> {
        let attr = self.verity_attr(inode, ino)?;
        // The attribute names where the descriptor sits and how long it is;
        // the descriptor is not at a fixed place, so it is located before it
        // is read rather than read from a guessed offset.
        let loc = verity::location::parse(&attr).map_err(|e| e.errno())?;
        let ceiling = crate::node::path::max_block(inode.addrs_per_inode()) * BLKSIZE as u64;
        verity::location::check(&loc, inode.size, ceiling).map_err(|e| e.errno())?;
        let desc = self.read_past_end(inode, ino, loc.pos, loc.size as usize)?;
        let v = verity::resolve(&attr, &desc, inode.size, ceiling).map_err(|e| e.errno())?;
        let p = merkle::Params::new(
            v.descriptor.hash_algorithm,
            v.descriptor.log_blocksize,
            &v.descriptor.salt[..v.descriptor.salt_size as usize],
            inode.size,
        )
        .map_err(|e| e.errno())?;
        let root = v.descriptor.root_hash[..p.digest_size].to_vec();
        Ok((p, root))
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
    /// Blocks wholly past the data are not attested and are not checked — the
    /// tree has no entry for them, and demanding one would fail every read of
    /// a file whose size is not a whole number of tree blocks.
    /// # C: O(blocks per file block * levels)
    pub(crate) fn verity_check(&self, inode: &Inode, ino: u32, index: u64, data: &[u8])
        -> Result<bool, Errno> {
        let (p, root) = self.verity_params(inode, ino)?;
        let nblocks = inode.size.div_ceil(p.block_size as u64);
        let per = BLKSIZE / p.block_size;
        for sub in 0..per {
            let bidx = index * per as u64 + sub as u64;
            if bidx >= nblocks { break; }
            let at = sub * p.block_size;
            let one = &data[at..at + p.block_size];
            if !self.verity_one(inode, ino, &p, &root, bidx, one)? { return Ok(false); }
        }
        Ok(true)
    }

    /// One attested block against the tree. # C: O(levels)
    fn verity_one(&self, inode: &Inode, ino: u32, p: &merkle::Params, root: &[u8], index: u64,
                  data: &[u8]) -> Result<bool, Errno> {
        // A file of one block or less has no tree: its own hash is the root.
        if merkle::is_flat(p) {
            return Ok(p.hash_block(data).map_err(|e| e.errno())?.as_bytes() == root);
        }
        let tree_at = verity::metadata_pos(inode.size);
        let mut err: Option<Errno> = None;
        let ok = merkle::verify_block(p, root, index, data, |tree_block| {
            let at = tree_at + tree_block * p.block_size as u64;
            match self.read_past_end(inode, ino, at, p.block_size) {
                Ok(b) => Ok(b),
                Err(e) => { err = Some(e); Err(verity::VerityError::Corrupted) }
            }
        });
        if let Some(e) = err { return Err(e); }
        ok.map_err(|e| e.errno())
    }
}

#[cfg(test)]
#[path = "../tests/veritysealed.rs"]
mod tests;
