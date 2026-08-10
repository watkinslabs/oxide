// Page pool + memory provider — the allocator a receive queue draws its
// packet buffers from, and the hook that lets something other than the page
// allocator supply them.
//
// A queue with no provider bound draws ordinary pages. A queue with one bound
// draws buffers the provider owns, so a device can place received payload
// straight into memory a userspace consumer already maps — the mechanism
// behind zero-copy receive.
//
// Module manifest:
//   netmem   — a buffer descriptor and the reference count that decides when
//              it goes back to its provider
//   provider — the provider contract and the parameters a binding carries
//   pool     — the pool itself: the allocation cache, alloc, and the release
//              that hands a buffer back once its last reference is gone

#[path = "page_pool/netmem.rs"]   pub mod netmem;
#[path = "page_pool/provider.rs"] pub mod provider;
#[path = "page_pool/pool.rs"]     pub mod pool;

pub use netmem::{NetIov, NetIovArea, Netmem};
pub use provider::{MemoryProvider, MpParams};
pub use pool::{PagePool, PP_ALLOC_CACHE_REFILL};
