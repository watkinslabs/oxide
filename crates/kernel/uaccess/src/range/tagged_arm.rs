// aarch64 kernel target: strip the pointer tag before the range check when the
// current task opted into the tagged-address ABI.
//
// The scheduler owns the per-task flag and sits ABOVE this crate, so the
// answer arrives by upcall. The symbol is weak-linked in effect: it is
// provided by `sched`, which every kernel image links.

extern "C" {
    /// Non-zero when the current task (or the absence of one) means a user
    /// pointer's top byte is a tag rather than part of the address.
    fn oxide_untag_user_pointers() -> u64;
}

/// # C: O(1)
pub fn for_range_check(addr: u64) -> u64 {
    // SAFETY: upcall into the scheduler's per-task flag; reads one atomic, takes no locks, and cannot re-enter this crate.
    if unsafe { oxide_untag_user_pointers() } == 0 { return addr; }
    // Linux `untagged_addr`: sign-extend bit 55 and use it as a mask, so a
    // user address loses its top byte and a kernel address is unchanged.
    addr & (((addr as i64) << 8 >> 8) as u64)
}
