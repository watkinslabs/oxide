//! Placing a compressed file's dirty pages: one CLUSTER at a time, once.
//!
//! Everything a compressed file defers happens here — the codec, the choice
//! between an image and plain blocks, and the addresses. A batch of pages is
//! grouped by the cluster each belongs to and each cluster is placed once,
//! whichever of its pages brought it here, because a cluster is one object and
//! placing it twice would write the same image to two different runs of blocks.
//!
//! Three conditions decide whether the cluster comes out as an image, and all
//! three are checked against state that already exists rather than against
//! anything this decides:
//!
//! - the MOUNT hands the decision to the filesystem rather than to the caller;
//! - the file's SIZE covers the whole cluster, so no block of the image is
//!   past the end of the file waiting to be rewritten by the next append;
//! - EVERY slot of the cluster is already held — a block, a reservation or the
//!   sentinel — and none of them is empty.
//!
//! The last one is what makes this safe rather than merely correct. An image
//! occupies the whole cluster's worth of slots, so making one out of a cluster
//! with an empty slot would have to take room HERE, at writeback, for a write
//! the caller was already told had landed. A cluster with an empty slot is
//! written plain instead, which needs no slot it does not already have.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use block::pagecache::PageOut;
use block::types::{BlockError, KResult};

use crate::filemap::Cache;
use crate::uapi::{BLKSIZE, NULL_ADDR};
use crate::volume::Volume;

use super::cluster::Geometry;
use super::plan;

impl<S: SectorSource> Volume<S> {
    /// Put a batch of one compressed file's pages on the medium.
    ///
    /// One slot of `results` per page, arriving prefilled with a failure, and
    /// every page of a cluster gets that cluster's own answer: a page whose
    /// cluster could not be placed is re-dirtied with the rest of it, because
    /// the image they share is all-or-nothing.
    /// # Ctx: process # Sleeps: y # C: O(pages + clusters * cluster bytes)
    pub(crate) fn writeback_compressed_pages(&mut self, ino: u32, pages: &[PageOut<'_>],
                                             results: &mut [KResult<()>],
                                             first_err: &mut Option<Errno>) {
        let Ok(inode) = self.read_inode(ino) else { return };
        let Ok(g) = self.geometry(&inode) else { return };
        let heads: Vec<u64> =
            pages.iter().map(|p| g.first_block(Cache::index_of(p))).collect();
        let mut placed: Vec<u64> = Vec::new();
        for (i, &head) in heads.iter().enumerate() {
            if placed.contains(&head) { continue; }
            placed.push(head);
            let outcome = self.place_cluster(ino, &g, head);
            if let Err(e) = outcome {
                if first_err.is_none() { *first_err = Some(e); }
            }
            for (j, &other) in heads.iter().enumerate().skip(i) {
                if other != head { continue; }
                results[j] = match outcome { Ok(()) => Ok(()), Err(_) => Err(BlockError::Eio) };
            }
        }
    }

    /// One cluster: its bytes, its shape, and the addresses that name it
    /// afterwards. # C: O(cluster bytes)
    fn place_cluster(&mut self, ino: u32, g: &Geometry, first: u64) -> Result<(), Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(ino)?;
        // A compressed cluster is enciphered as its stored IMAGE, which means
        // the cipher would have to go on inside the codec's output rather than
        // around it. The write path refuses such a file outright; refusing
        // here too keeps a page that reached the mapping by another road from
        // landing in the clear.
        if inode.encrypted() { return Err(Errno::Eopnotsupp); }
        let old = self.cluster_addrs(&inode, ino, g, first)?;
        let held: Vec<bool> = old.iter().map(|&a| a != NULL_ADDR).collect();
        let plain = self.cluster_now(ino, g, first)?;
        let compress = self.opts.compress.mode == crate::opts::CompressMode::Fs
            && held.iter().all(|&h| h)
            && plan::may_compress(first, g.blocks(), inode.size, BLKSIZE);
        // The pages STAY: this writer is putting the bytes it holds at the
        // addresses it is choosing, so the mapping and the medium agree, and
        // dropping them would throw away the only copy of a write.
        self.store_cluster_placed(ino, g, first, &plain, inode.size, &held, compress)
    }
}
