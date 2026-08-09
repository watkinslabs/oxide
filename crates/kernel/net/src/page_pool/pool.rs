// The pool itself: an allocation cache in front of the provider, and the
// release path that returns a buffer once its last reference is gone.
//
// The cache exists because a provider refill is a batch operation — it walks a
// shared ring or a freelist — while a receive path takes one buffer at a time.
// Refilling in batches and handing out singly is what keeps the per-packet
// cost off the provider.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as SocketLockClass};

use super::netmem::Netmem;
use super::provider::{MemoryProvider, MpParams};
use crate::netdev::NetError;

/// Buffers one provider refill asks for.
pub const PP_ALLOC_CACHE_REFILL: usize = 64;

pub struct PagePool {
    provider: Arc<dyn MemoryProvider>,
    /// Buffers taken from the provider and not yet handed out.
    cache: Spinlock<Vec<Netmem>, SocketLockClass>,
    /// Buffer size this pool hands out.
    buf_len: u32,
}

impl PagePool {
    /// Build a pool over a provider and let the provider accept or refuse it.
    /// A refused pool is dropped without ever calling `destroy`, matching the
    /// reference's "init failed, nothing to undo" shape. # C: O(1)
    pub fn create(p: &MpParams) -> Result<Arc<Self>, NetError> {
        let buf_len = if p.rx_page_size != 0 { p.rx_page_size } else { p.ops.rx_buf_len() };
        let pool = Arc::new(Self {
            provider: Arc::clone(&p.ops),
            cache: Spinlock::new(Vec::new()),
            buf_len,
        });
        p.ops.init(&pool)?;
        Ok(pool)
    }

    /// Buffer size this pool hands out. # C: O(1)
    pub fn buf_len(&self) -> u32 { self.buf_len }

    /// Whether this pool draws from `p`'s provider. # C: O(1)
    pub fn provided_by(&self, p: &Arc<dyn MemoryProvider>) -> bool {
        Arc::ptr_eq(&self.provider, p)
    }

    /// Take one buffer. The cache answers when it can; otherwise the provider
    /// refills it. A fresh buffer carries exactly one reference — the one the
    /// caller now holds. # C: O(1) amortised
    pub fn alloc_netmem(&self) -> Option<Netmem> {
        {
            let mut c = self.cache.lock();
            if let Some(nm) = c.pop() { nm.niov().fragment(1); return Some(nm); }
        }
        let mut batch = Vec::new();
        let got = self.provider.alloc_netmems(self, &mut batch, PP_ALLOC_CACHE_REFILL);
        if got == 0 { return None; }
        let nm = batch.pop()?;
        if !batch.is_empty() {
            let mut c = self.cache.lock();
            c.append(&mut batch);
        }
        nm.niov().fragment(1);
        Some(nm)
    }

    /// Give the pool a buffer the provider already accounted for, without
    /// going through `alloc`. # C: O(1)
    pub fn place_in_cache(&self, nm: Netmem) { self.cache.lock().push(nm); }

    /// Release one reference. The buffer goes back to the provider on the
    /// transition to zero and never before, so a buffer a device still holds
    /// cannot be handed to a second owner. # C: O(1)
    pub fn put_netmem(&self, nm: &Netmem) {
        if nm.niov().unref_and_test() { self.provider.release_netmem(nm); }
    }

    /// Drain the cache back to the provider and tell it the pool is gone.
    /// # C: O(N_cached)
    pub fn destroy(&self) {
        let cached: Vec<Netmem> = core::mem::take(&mut *self.cache.lock());
        for nm in cached.iter() { self.provider.release_netmem(nm); }
        self.provider.destroy();
    }
}

#[cfg(test)]
#[path = "pool/tests.rs"]
mod tests;
