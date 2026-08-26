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
mod admit;
mod resolve;

#[cfg(not(feature = "debug-faultcost"))]
pub use entry::user_fault_handler;

/// `debug-faultcost` wrapper: time every architecture fault entry and split
/// resolved from unresolved. # C: entry cost plus two clock reads
#[cfg(all(feature = "debug-faultcost", target_arch = "x86_64"))]
pub fn user_fault_handler(vec: u64, err: u64, rip: u64, cr2: u64) -> bool {
    let t0 = crate::faultcost::start();
    let handled = entry::user_fault_handler(vec, err, rip, cr2);
    // x86 #PF error code: bit0 present (a protection violation, not an absent
    // page), bit1 write.
    let class = (((err & 1) << 1) | ((err >> 1) & 1)) as usize;
    crate::faultcost::record(t0, handled, class);
    handled
}

/// # C: entry cost plus two clock reads
#[cfg(all(feature = "debug-faultcost", target_arch = "aarch64"))]
pub fn user_fault_handler(esr: u64, far: u64, elr: u64) -> bool {
    let t0 = crate::faultcost::start();
    let handled = entry::user_fault_handler(esr, far, elr);
    // ESR: WnR (bit 6) is the write side; a permission fault (DFSC 0b0011xx)
    // is the protection class, translation faults are the absent class.
    let write = (esr >> 6) & 1;
    let present = u64::from((esr & 0x3c) == 0x0c);
    crate::faultcost::record(t0, handled, ((present << 1) | write) as usize);
    handled
}
pub(in crate::user_as) use resolve::do_handle;
