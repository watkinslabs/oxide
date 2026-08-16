//! Rewriting every cluster of one file, compressed or plain, on demand.
//!
//! Only for a mount that hands the decision to the caller. Where the MOUNT
//! decides, every write already comes out in whichever shape the mount asked
//! for and a command to rewrite the file would be rewriting it into the shape
//! it is already in; where the CALLER decides, a file is written plain and
//! compressed afterwards — which is the whole point of the arrangement, and
//! why these two commands exist at all.
//!
//! Neither walk is all-or-nothing, and neither can be. A cluster that has been
//! rewritten is on the medium; reporting the whole call as failed because a
//! later one could not be would tell the caller its file is untouched when
//! half of it has changed shape. The error is reported and what landed stays.
//!
//! Which clusters each walk touches is not symmetric:
//!
//! - COMPRESSING skips every cluster that is not `cluster_size` real blocks.
//!   A cluster with a hole in it is not a cluster the image could cover, and a
//!   cluster already compressed has nothing to gain.
//! - DECOMPRESSING touches exactly the clusters that carry the sentinel.

use alloc::vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::{BLKSIZE, COMPRESS_ADDR};
use crate::volume::Volume;

use super::cluster::{is_data_addr, Geometry};
use super::plan;

/// Which way a rewrite is going.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Shape {
    Compressed,
    Plain,
}

impl<S: SectorSource> Volume<S> {
    /// Compress every cluster of `ino` that can be compressed.
    ///
    /// Reports the clusters rewritten, which is zero for a file already in
    /// that shape.
    /// # C: O(file bytes)
    pub fn compress_file(&mut self, ino: u32) -> Result<u64, Errno> {
        self.rewrite_clusters(ino, Shape::Compressed)
    }

    /// Store every compressed cluster of `ino` plain.
    /// # C: O(file bytes)
    pub fn decompress_file(&mut self, ino: u32) -> Result<u64, Errno> {
        self.rewrite_clusters(ino, Shape::Plain)
    }

    /// # C: O(file bytes)
    fn rewrite_clusters(&mut self, ino: u32, want: Shape) -> Result<u64, Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(ino)?;
        let g = self.geometry(&inode)?;
        if inode.inline_data() { self.convert_inline(ino)?; }
        let size = self.read_inode(ino)?.size;
        let last = size.div_ceil(BLKSIZE as u64);
        let all = vec![true; g.blocks()];
        let mut done = 0u64;
        let mut first = 0u64;
        while first < last {
            if self.cluster_wants_rewriting(ino, &g, first, want, size)? {
                let inode = self.read_inode(ino)?;
                let plainbytes = self.cluster_bytes(&inode, ino, &g, first)?;
                self.store_cluster_shaped(ino, &g, first, &plainbytes, size, &all,
                                          want == Shape::Compressed)?;
                done += 1;
            }
            first += g.blocks() as u64;
        }
        Ok(done)
    }

    /// Whether the cluster starting at `first` is one this walk touches.
    /// # C: O(cluster blocks)
    fn cluster_wants_rewriting(&self, ino: u32, g: &Geometry, first: u64, want: Shape, size: u64)
        -> Result<bool, Errno> {
        let inode = self.read_inode(ino)?;
        let addrs = self.cluster_addrs(&inode, ino, g, first)?;
        let compressed = addrs.first() == Some(&COMPRESS_ADDR);
        Ok(match want {
            Shape::Plain => compressed,
            Shape::Compressed => {
                // Every block real and the whole cluster inside the file: the
                // two conditions an image has to satisfy before one is worth
                // making, checked here so a cluster that cannot be compressed
                // is not read and written back unchanged.
                !compressed
                    && addrs.iter().all(|&a| is_data_addr(a))
                    && plan::may_compress(first, g.blocks(), size, BLKSIZE)
            }
        })
    }
}
