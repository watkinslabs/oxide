// The memory-provider contract a bound device receive queue draws through.
//
// A refill comes from the caller first and the freelist second, in that order
// and never the other way: buffers the caller has explicitly handed back are
// the ones it is finished reading, so consuming them first keeps the caller's
// own reads and the device's writes from chasing each other around the area.
// The freelist is what is left when the caller has handed nothing back, and
// running dry there is what the no-buffers notification reports.

use alloc::sync::Arc;
use alloc::vec::Vec;

use net::netdev::NetError;
use net::page_pool::{MemoryProvider, Netmem, PagePool};

use crate::io_uring_abi::zcrx::ZCRX_NOTIF_NO_BUFFERS;

use super::ifq::ZcrxIfq;

impl MemoryProvider for ZcrxIfq {
    /// Fill from the refill queue, then from the freelist. # C: O(to_alloc)
    fn alloc_netmems(&self, _pool: &PagePool, out: &mut Vec<Netmem>, to_alloc: usize) -> usize {
        let before = out.len();
        // The refill queue: each entry the caller really owned and nobody else
        // holds becomes a buffer this pool can hand to the device.
        self.rq.take(to_alloc, |rqe| {
            if !self.return_rqe(&rqe) { return; }
            // `return_rqe` put it on the freelist; take it straight back out,
            // so the ordering above is the only thing that decides which
            // buffer a device gets.
            if let Some(idx) = self.area.get_free() {
                self.area.nia.niovs[idx as usize].fragment(1);
                self.area.nia.niovs[idx as usize].set_bound();
                out.push(Netmem { area: Arc::clone(&self.area.nia), idx });
            }
        });
        while out.len() - before < to_alloc {
            let Some(idx) = self.area.get_free() else { break };
            self.area.nia.niovs[idx as usize].fragment(1);
            self.area.nia.niovs[idx as usize].set_bound();
            out.push(Netmem { area: Arc::clone(&self.area.nia), idx });
        }
        let got = out.len() - before;
        if got == 0 { self.send_notif(ZCRX_NOTIF_NO_BUFFERS); }
        got
    }

    /// # C: O(1)
    fn release_netmem(&self, nm: &Netmem) { self.area.put_free(nm.idx); }

    /// A pool may only be built over an instance whose buffers are the size
    /// the queue was told to expect. # C: O(1)
    fn init(&self, pool: &PagePool) -> Result<(), NetError> {
        if pool.buf_len() != self.rx_buf_len() { return Err(NetError::Einval); }
        Ok(())
    }

    /// # C: O(1)
    fn destroy(&self) {}

    /// The queue is gone. The instance survives — the caller still has its
    /// area mapped and may still be reading buffers out of it — so nothing is
    /// freed here; only the binding is forgotten. # C: O(1)
    fn uninstall(&self) { let _ = self.binding.lock().take(); }

    /// # C: O(1)
    fn rx_buf_len(&self) -> u32 { ZcrxIfq::rx_buf_len(self) }
}
