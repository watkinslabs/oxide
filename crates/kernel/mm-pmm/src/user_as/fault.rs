// User page-fault handling.
//
// Module manifest:
//   `entry`   — architecture fault-vector entry, dispatch into the running
//               task's address space, and the unresolved-fault signal.
//   `resolve` — settling swap and migration leaves, userfaultfd interception,
//               and the call into the VMM fill for one address space.

pub(super) const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
pub(super) const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

mod entry;
mod resolve;

pub use entry::user_fault_handler;
pub(in crate::user_as) use resolve::do_handle;
