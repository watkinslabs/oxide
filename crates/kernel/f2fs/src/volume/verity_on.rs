//! Turning verity on: building the tree a file's reads will be checked
//! against, and sealing the file behind it.
//!
//! The order here is the whole safety property. The tree and the descriptor
//! are written FIRST, as ordinary file blocks past the data; the attribute
//! that points at the descriptor goes down next; the inode flag goes last.
//! A crash at any point therefore leaves either a file with no flag — which
//! reads as an ordinary file, its metadata a sparse tail nobody looks at — or
//! a fully sealed one. Setting the flag first would leave a file that claims
//! attestation and has none, and every read of it would fail.
//!
//! The tree is written ROOT FIRST, matching how the reader indexes it, and
//! each level's blocks are hashed to produce the level above. The last block
//! of any level, and the file's own last data block, are zero-padded to a
//! whole block before hashing — the hash covers the block, not the bytes that
//! happen to be live in it.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::{BLKSIZE, XATTR_INDEX_VERITY};
use crate::verity::descriptor::Descriptor;
use crate::verity::merkle::{self, MAX_DIGEST_SIZE};
use crate::verity::walk::digest_array;
use crate::verity::uapi::{LOCATION_VERSION, MAX_ROOT_HASH, MAX_SALT, XATTR_NAME};
use crate::verity::{self, VerityError};
use crate::xattr::{self, Attr};

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Seal `ino` under a hash tree, and return the root the reader will
    /// check against.
    ///
    /// Refuses a file that is already sealed rather than building a second
    /// tree over it: the first tree's descriptor would still be there, and
    /// which of the two a reader used would depend on where each landed.
    /// # C: O(file bytes) hashed, O(file bytes / arity) written
    pub fn enable_verity(&mut self, ino: u32, hash_alg: u8, log_blocksize: u8, salt: &[u8])
        -> Result<Vec<u8>, Errno> {
        self.enable_verity_signed(ino, hash_alg, log_blocksize, salt, &[])
    }

    /// Seal `ino`, appending a built-in signature over the descriptor.
    ///
    /// The signature is checked HERE, against the same policy a later read
    /// checks it against. Writing one that would be refused on the next read
    /// produces a file nobody can open, so the refusal happens while the
    /// metadata can still be taken back off the file.
    /// # C: O(file bytes) hashed, O(chain * rsa)
    pub fn enable_verity_signed(&mut self, ino: u32, hash_alg: u8, log_blocksize: u8,
                                salt: &[u8], sig: &[u8]) -> Result<Vec<u8>, Errno> {
        self.writable_or_err()?;
        // A file with an atomic-write span open is about to have its contents
        // replaced, so a tree built over them now would attest to bytes the
        // commit is going to move out from under it.
        crate::atomic::policy::enable_verity(self.is_atomic_file(ino))?;
        let inode = self.read_inode(ino)?;
        verity::access::enable(inode.flags).map_err(verity::access::errno)?;
        // The tree is addressed through the file's own block index, so a file
        // whose data lives in the inode has nowhere to put it.
        self.convert_inline(ino)?;
        let inode = self.read_inode(ino)?;
        let p = merkle::Params::new(hash_alg, log_blocksize, salt, inode.size)
            .map_err(|e| e.errno())?;
        if p.block_size > BLKSIZE { return Err(VerityError::BadBlockSize.errno()); }

        let tree_at = verity::metadata_pos(inode.size);
        let root = self.build_tree(&inode, ino, &p, tree_at)?;

        if salt.len() > MAX_SALT { return Err(Errno::Einval); }
        let mut d = Descriptor {
            version: crate::verity::uapi::DESCRIPTOR_VERSION,
            hash_algorithm: hash_alg,
            log_blocksize,
            salt_size: salt.len() as u8,
            sig_size: sig.len() as u32,
            data_size: inode.size,
            root_hash: [0u8; MAX_ROOT_HASH],
            salt: [0u8; MAX_SALT],
        };
        d.root_hash[..root.len()].copy_from_slice(&root);
        d.salt[..salt.len()].copy_from_slice(salt);
        // Build the info from the finished descriptor exactly as a reader
        // would, before anything points at it: the same code path that will
        // accept or refuse this file later decides now, while the metadata
        // can still be taken back off.
        let info = match verity::Info::open(&d, sig, inode.size, &self.verity_policy) {
            Ok(i) => i,
            Err(e) => { self.unwrite_metadata(ino, inode.size)?; return Err(e.errno()); }
        };
        let bytes = verity::descriptor::encode(&d, sig);
        let desc_at = tree_at + p.tree_size;
        self.write_metadata(ino, desc_at, &bytes)?;

        // The pointer, then the flag: a reader that sees the flag must be
        // able to find the descriptor it implies.
        let loc = verity::location::Location {
            version: LOCATION_VERSION,
            size: bytes.len() as u32,
            pos: desc_at,
        };
        self.put_verity_attr(ino, &verity::location::encode(&loc))?;
        self.stamp_inode(ino, |b| {
            let cur = crate::uapi::le32(b, crate::uapi::I_FLAGS).unwrap_or(0);
            b[crate::uapi::I_FLAGS..crate::uapi::I_FLAGS + 4]
                .copy_from_slice(&(cur | crate::flags::F2FS_VERITY_FL).to_le_bytes());
        })?;
        // The inode number now names a different thing than it did a moment
        // ago, so whatever was held for it is stale by construction. The
        // fresh info replaces it rather than being left to be re-derived,
        // because it was just built and is known to be the one a read wants.
        self.verity_cache.borrow_mut().insert(ino, info);
        // Every page of this file in the mapping was filed BEFORE the file was
        // sealed and therefore without an attestation. Serving one afterwards
        // would hand back bytes no tree ever attested to, under a flag that
        // says they were — the file is dropped from the mapping so the next
        // read of each page is checked as a read of a sealed file.
        self.data_cache.forget_inode(ino);
        Ok(root)
    }

    /// Take the metadata back off a file whose sealing did not complete.
    ///
    /// Nothing points at those blocks — the attribute and the flag go down
    /// last — so leaving them would only charge the file for space no reader
    /// will ever look at, and would put stale metadata under a second attempt.
    /// # C: O(blocks freed)
    fn unwrite_metadata(&mut self, ino: u32, size: u64) -> Result<(), Errno> {
        self.verity_cache.borrow_mut().forget(ino);
        self.truncate_file(ino, size)
    }

    /// Hash the data, then each level in turn, writing every block as it is
    /// finished. Returns the root hash.
    /// # C: O(file bytes)
    fn build_tree(&mut self, inode: &crate::node::Inode, ino: u32, p: &merkle::Params,
                  tree_at: u64) -> Result<Vec<u8>, Errno> {
        // An empty file has no blocks to attest to, so its root is the zero
        // digest rather than the hash of nothing.
        if inode.size == 0 { return Ok(vec![0u8; p.digest_size]); }
        let bs = p.block_size;
        let nblocks = inode.size.div_ceil(bs as u64);
        let mut below: Vec<[u8; MAX_DIGEST_SIZE]> = Vec::new();
        let mut buf = vec![0u8; bs];
        for i in 0..nblocks {
            buf.iter_mut().for_each(|b| *b = 0);
            let at = i * bs as u64;
            let take = (inode.size - at).min(bs as u64) as usize;
            self.read_file(inode, ino, at, &mut buf[..take])?;
            below.push(digest_array(&p.hash_block(&buf).map_err(|e| e.errno())?));
        }
        // Levels are built bottom-up but STORED root-first, so each level's
        // blocks go at the start the geometry already computed for it.
        for level in 0..p.num_levels {
            let per = 1usize << p.log_arity;
            let mut above: Vec<[u8; MAX_DIGEST_SIZE]> = Vec::new();
            for (n, chunk) in below.chunks(per).enumerate() {
                let mut block = vec![0u8; bs];
                for (k, dg) in chunk.iter().enumerate() {
                    block[k * p.digest_size..(k + 1) * p.digest_size]
                        .copy_from_slice(&dg[..p.digest_size]);
                }
                let at = tree_at + (p.level_start[level] + n as u64) * bs as u64;
                self.write_metadata(ino, at, &block)?;
                above.push(digest_array(&p.hash_block(&block).map_err(|e| e.errno())?));
            }
            below = above;
        }
        Ok(below[0][..p.digest_size].to_vec())
    }

    /// Write bytes past the file's own length, leaving the length alone.
    ///
    /// The metadata is not file content, so nothing here extends the size —
    /// which is also what keeps the boundary between data and metadata where
    /// the tree was built against.
    /// # C: O(bytes)
    fn write_metadata(&mut self, ino: u32, at: u64, bytes: &[u8]) -> Result<(), Errno> {
        let mut done = 0usize;
        while done < bytes.len() {
            let pos = at + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(bytes.len() - done);
            self.write_one_block(ino, index, skew, &bytes[done..done + take])?;
            done += take;
        }
        Ok(())
    }

    /// Store the location record under the attribute index the format
    /// reserves for it.
    ///
    /// The index carries no name prefix, so no caller-supplied name can reach
    /// it and it cannot be written through the ordinary attribute path.
    /// # C: O(region bytes)
    fn put_verity_attr(&mut self, ino: u32, value: &[u8]) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let area = self.xattr_area(&inode, ino)?;
        let mut attrs = xattr::list(&area).map_err(|_| Errno::Eio)?;
        if attrs.iter().any(|a| a.index == XATTR_INDEX_VERITY && a.name == XATTR_NAME) {
            return Err(Errno::Eexist);
        }
        attrs.push(Attr {
            index: XATTR_INDEX_VERITY,
            name: XATTR_NAME.to_vec(),
            value: value.to_vec(),
        });
        self.store_xattrs(ino, &attrs)
    }
}

#[cfg(test)]
#[path = "../tests/verityon.rs"]
mod tests;
