// Every other target: no tagged-address ABI, so the address reaches the range
// check exactly as userspace supplied it.

/// # C: O(1)
pub fn for_range_check(addr: u64) -> u64 { addr }
