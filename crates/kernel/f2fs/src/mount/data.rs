//! The way back from a dirty data page to the mount that owns it.
//!
//! A page dirtied by a buffered write is reached from two directions. This
//! filesystem's own flush points — a checkpoint, an `fsync`, a truncate, the
//! cleaner — already hold the volume and hand their batch straight to it. The
//! MACHINE's flusher and page reclaim arrive holding nothing at all, and
//! without this they would meet a dirty page they could not place: the flusher
//! would walk it forever and reclaim could never evict it.

use alloc::sync::Arc;

use block::pagecache::PageOut;
use block::types::KResult;

use crate::filemap::{DataHost, NodeHost};

use super::F2fs;

impl DataHost for F2fs {
    /// Take the mount and place the batch.
    ///
    /// Entered from OUTSIDE this filesystem, holding none of its locks, which
    /// is exactly why taking the volume here is safe and why the flush points
    /// inside it must not come this way.
    /// # Ctx: process # Sleeps: y # C: O(pages) blocks
    fn writeback_data(&self, ino: u32, pages: &[PageOut<'_>], results: &mut [KResult<()>]) {
        let mut first = None;
        let mut v = self.volume.lock();
        v.set_clock(super::write::now().0);
        v.writeback_data_pages(ino, pages, results, &mut first);
    }

    /// # C: O(devices)
    fn sync_data_medium(&self) -> KResult<()> {
        for dev in &self.devs { dev.flush()?; }
        Ok(())
    }
}

impl NodeHost for F2fs {
    /// The same for NODE pages, which reclaim and the flusher reach by the
    /// same route and for the same reason: a dirty node page they cannot place
    /// is one the flusher walks forever and reclaim can never evict.
    /// # Ctx: process # Sleeps: y # C: O(pages) blocks
    fn writeback_nodes(&self, pages: &[PageOut<'_>], results: &mut [KResult<()>]) {
        let mut first = None;
        let mut v = self.volume.lock();
        v.set_clock(super::write::now().0);
        v.writeback_node_pages(pages, results, &mut first);
    }

    /// # C: O(devices)
    fn sync_node_medium(&self) -> KResult<()> {
        for dev in &self.devs { dev.flush()?; }
        Ok(())
    }
}

impl F2fs {
    /// Give the mapping the way back to this mount.
    ///
    /// Cannot be part of building the mount: the mapping belongs to the volume
    /// and exists before there is a filesystem to point at, and the reference
    /// back has to be the one an `Arc` hands out rather than a second object.
    /// # C: O(1)
    #[inline(never)]
    pub(crate) fn adopt_data_pages(self: &Arc<Self>) {
        let cache = self.volume.lock().data_cache();
        cache.set_host(Arc::downgrade(self) as alloc::sync::Weak<dyn DataHost>);
        let nodes = self.volume.lock().node_cache();
        nodes.set_host(Arc::downgrade(self) as alloc::sync::Weak<dyn NodeHost>);
    }

    /// Act on the machine's dirty state after a write.
    ///
    /// Called with the volume's lock DROPPED. Over the dirty limit this writes
    /// back, which re-enters this mount through the target above, so a caller
    /// still holding the guard would wait on itself.
    /// # Ctx: process # Sleeps: y # C: O(pages written)
    pub(crate) fn balance_data(&self, ino: u32) {
        let cache = self.volume.lock().data_cache();
        cache.balance(ino);
    }
}
