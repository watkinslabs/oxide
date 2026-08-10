// The memory-provider contract: what a pool asks of whoever supplies its
// buffers, and the parameters a receive-queue binding carries.
//
// The provider owns the memory. The pool owns the reference counting and the
// allocation cache. Neither knows what the other's memory is for, which is
// what lets one provider serve a device queue and a userspace consumer at the
// same time.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::netmem::Netmem;
use super::pool::PagePool;
use crate::netdev::NetError;

/// Callbacks a pool makes into its provider.
pub trait MemoryProvider: Send + Sync {
    /// Fill `out` with up to `to_alloc` buffers, returning how many were
    /// added. Zero means the provider has nothing to give right now, which is
    /// a receive drop, not an error. # C: O(to_alloc)
    fn alloc_netmems(&self, pool: &PagePool, out: &mut Vec<Netmem>, to_alloc: usize) -> usize;

    /// Take one buffer back; its last pool reference is gone. # C: O(1)
    fn release_netmem(&self, nm: &Netmem);

    /// Accept, or refuse, the pool being built over this provider. # C: O(1)
    fn init(&self, pool: &PagePool) -> Result<(), NetError>;

    /// The pool is gone. # C: O(1)
    fn destroy(&self);

    /// The queue binding is being torn down — the provider outlives it and
    /// must stop expecting the device to return anything. # C: O(1)
    fn uninstall(&self);

    /// Buffer size this provider hands out, in bytes. # C: O(1)
    fn rx_buf_len(&self) -> u32;
}

/// What a receive queue records about its bound provider — Linux
/// `struct pp_memory_provider_params`.
#[derive(Clone)]
pub struct MpParams {
    pub ops: Arc<dyn MemoryProvider>,
    /// Buffer size the binding asks the device for, or zero for the device's
    /// own default. Non-zero requires a device that can be told.
    pub rx_page_size: u32,
}

impl MpParams {
    /// Whether two bindings name the same provider — the identity a close
    /// checks before clearing a queue it may no longer own. # C: O(1)
    pub fn same(&self, other: &MpParams) -> bool { Arc::ptr_eq(&self.ops, &other.ops) }
}
