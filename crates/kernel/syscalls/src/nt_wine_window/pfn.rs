//! PFN table ABI: pointer slots remain 64-bit; byte counts are ULONGs.

pub(crate) const CLIENT_PROCS_BYTES: u64 = 17 * 8;
pub(crate) const WORKERS_BYTES: u64 = 11 * 8;
const PFN_BYTES: u64 = 8;

/// # C: O(1)
pub(crate) fn initialize_args(mut args: [u64; 6]) -> Option<[u64; 6]> {
    for (index, limit) in [(1, CLIENT_PROCS_BYTES), (3, CLIENT_PROCS_BYTES), (5, WORKERS_BYTES)] {
        args[index] = args[index] as u32 as u64;
        if args[index] > limit || args[index] % PFN_BYTES != 0 { return None; }
    }
    Some(args)
}

/// # C: O(bytes / 8)
pub(crate) fn validate_table(base: u64, bytes: u64, mut readable: impl FnMut(u64) -> bool) -> bool {
    for index in 0..bytes / PFN_BYTES {
        let Some(address) = base.checked_add(index * PFN_BYTES) else { return false; };
        if !readable(address) { return false; }
    }
    true
}

#[cfg(test)]
#[path = "tests/pfn.rs"]
mod tests;
