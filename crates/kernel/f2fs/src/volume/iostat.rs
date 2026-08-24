//! Charging one request to the layer that asked for it.
//!
//! The sites that move blocks say what KIND of traffic they are, because the
//! address does not: a node block and a page of file data sit side by side in
//! the main area, and the same block written by the cleaner and by an
//! application is two different answers to "which layer generated this".
//!
//! Off by default, and the guard is the first thing every site does. The
//! accounting costs a pair of additions per block, and one site — the
//! application write — costs an inode read to learn whether the file is
//! compressed, so it is paid only by a reader that asked for the report.

use sectors::SectorSource;

use crate::stats::iostat::Io;

use super::Volume;

const SECTOR_BYTES: u64 = 512;

#[cfg(test)]
#[path = "../tests/iostatwire.rs"]
mod tests;

impl<S: SectorSource> Volume<S> {
    /// Record one successful physical write for the durable lifetime report.
    /// # C: O(1)
    pub(crate) fn record_physical_write(&self, bytes: usize) {
        let sectors = (bytes as u64) / SECTOR_BYTES;
        self.sectors_written_since_cp.set(
            self.sectors_written_since_cp.get().saturating_add(sectors));
    }

    /// Current lifetime writes, including sectors since the last checkpoint.
    /// # C: O(1)
    pub fn lifetime_write_kbytes(&self) -> u64 {
        self.lifetime_write_kbytes.saturating_add(
            self.sectors_written_since_cp.get() >> 1)
    }

    /// Fold this mount's physical writes into the durable lifetime total.
    /// # C: O(1)
    pub(crate) fn checkpoint_lifetime_write_kbytes(&mut self) {
        self.lifetime_write_kbytes = self.lifetime_write_kbytes.saturating_add(
            self.sectors_written_since_cp.replace(0) >> 1);
    }

    /// Record one request of `kind` carrying `bytes`.
    ///
    /// `compressed` adds the compressed twin of the kind where one exists, so
    /// a compressed file's traffic appears under both its plain kind and its
    /// compressed one.
    /// # C: O(1)
    pub(crate) fn io_account(&self, kind: Io, bytes: u64, compressed: bool) {
        self.counters.borrow_mut().iostat.update(kind, bytes, compressed);
    }

    /// Record one served read of `order` blocks. # C: O(1)
    pub(crate) fn io_read_folio(&self, order: usize) {
        self.counters.borrow_mut().iostat.read_folio(order);
    }

    /// Whether this mount is accounting at all. # C: O(1)
    pub fn iostat_enabled(&self) -> bool { self.counters.borrow().iostat.enabled }

    /// Turn accounting on or off, as the published control does.
    ///
    /// Turning it OFF forgets the totals, and that is the contract a tool
    /// depends on: a window is measured by turning the accounting off and then
    /// on, so totals carried across the switch would add the previous window
    /// to the new one and there would be no way to ask for a fresh count.
    /// Turning it on keeps what is there, which after a disable is nothing.
    /// # C: O(N kinds)
    pub fn set_iostat_enabled(&mut self, on: bool) {
        let mut c = self.counters.borrow_mut();
        c.iostat.enable(on);
        if !on { c.iostat.reset(); }
    }

    /// Whether a main-area write now belongs to the cleaner rather than to
    /// the layer that asked for it.
    ///
    /// The cleaner's copies are the same bytes going to a new address, so
    /// they are not the file's traffic and not the node layer's; the mark the
    /// migration already sets is what tells them apart, rather than a second
    /// flag a migration site would have to remember to raise.
    /// # C: O(1)
    pub(crate) fn io_gc_kind(&self, plain: Io, gc: Io) -> Io {
        if self.segstate.gc_moving { gc } else { plain }
    }
}
