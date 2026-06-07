// Kernel-embedded ext4 image block device. Kernel-only (the
// `&'static` rootfs snapshot lives in .rodata); hosted resolution
// tests publish a fixture Mount via `set_test_mount`/`Ext4Mount::open`
// over a `MemDisk` instead.

use alloc::sync::Arc;
use block::{BlockDevice, BlockOp, BlockRequest};
use block::types::{BlockError, KResult};
use ::sync as sync;

/// Block device over the kernel-embedded ext4 image. Reads come
/// straight from the `&'static [u8]` snapshot (in .rodata — no copy),
/// so the image can be any size without a giant boot-time heap alloc.
/// Writes are stored in a SPARSE per-block overlay (BTreeMap keyed by
/// block index) — only modified blocks consume heap, so boot/login
/// writes (superblock, a few inodes) cost KiB, not the whole image.
pub struct ImageDisk {
    base:     &'static [u8],
    overlay:  sync::Spinlock<alloc::collections::BTreeMap<u64, alloc::boxed::Box<[u8]>>, sync::Inode>,
    blk_size: u32,
}

impl ImageDisk {
    /// Wrap a `'static` ext4 snapshot — no copy; writes land in the overlay.
    /// # C: O(1)
    pub fn from_static(bytes: &'static [u8], blk_size: u32) -> Arc<Self> {
        Arc::new(Self {
            base:     bytes,
            overlay:  sync::Spinlock::new(alloc::collections::BTreeMap::new()),
            blk_size,
        })
    }

    /// Read one block into `out` (= blk_size bytes): overlay if present, else base.
    /// # C: O(log W) overlay lookup
    fn read_block(&self, blk: u64, out: &mut [u8]) {
        if let Some(b) = self.overlay.lock().get(&blk) { out.copy_from_slice(b); return; }
        let bs = self.blk_size as usize;
        let off = blk as usize * bs;
        out.fill(0);
        if off < self.base.len() {
            let n = core::cmp::min(bs, self.base.len() - off);
            out[..n].copy_from_slice(&self.base[off..off + n]);
        }
    }
}

impl BlockDevice for ImageDisk {
    fn block_size(&self) -> u32 { self.blk_size }
    fn capacity_blocks(&self) -> u64 {
        (self.base.len() as u64) / (self.blk_size as u64)
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let bs  = self.blk_size as usize;
        let len = (req.len_blocks as usize) * bs;
        let cap = self.base.len();
        if (req.start_block as usize * bs) + len > cap { return Err(BlockError::Eio); }
        match req.op {
            BlockOp::Read => {
                if req.buffer.len() < len { req.buffer.resize(len, 0); }
                for i in 0..req.len_blocks as usize {
                    self.read_block(req.start_block + i as u64, &mut req.buffer[i * bs..(i + 1) * bs]);
                }
                Ok(())
            }
            BlockOp::Write => {
                if req.buffer.len() < len { return Err(BlockError::Einval); }
                let mut g = self.overlay.lock();
                for i in 0..req.len_blocks as usize {
                    let blk = req.start_block + i as u64;
                    g.insert(blk, req.buffer[i * bs..(i + 1) * bs].to_vec().into_boxed_slice());
                }
                Ok(())
            }
            BlockOp::Flush   => Ok(()),
            BlockOp::Discard => Ok(()),
        }
    }
    fn flush(&self) -> KResult<()> { Ok(()) }
}
