//! Complete Windows argument lists for raw win32u entries on either architecture.
//!
//! The architectural entry hands each router only the arguments its register
//! snapshot carries. A signature longer than that continues on the user stack
//! at the logical index the signature gives it, and this is the one place that
//! reads it.

/// The longest Windows signature the raw entry admits.
pub(crate) const MAX_RAW_ARGUMENTS: usize = 17;

/// Collect a complete argument list, reading the tail the caller does not hold
/// from the user stack. A stack word that cannot be read fails the call rather
/// than substituting a zero. # C: O(N_arguments)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn gather(args: &[u64], count: usize) -> Option<[u64; MAX_RAW_ARGUMENTS]> {
    collect(args, count, crate::nt_dispatch::stack_argument)
}

/// # C: O(N_arguments)
pub(crate) fn collect(args: &[u64], count: usize, mut stack: impl FnMut(usize) -> Option<u64>)
    -> Option<[u64; MAX_RAW_ARGUMENTS]> {
    let mut full = [0u64; MAX_RAW_ARGUMENTS];
    for index in 0..count.min(MAX_RAW_ARGUMENTS) {
        full[index] = match args.get(index) { Some(value) => *value, None => stack(index)? };
    }
    Some(full)
}

#[cfg(test)]
#[path = "tests/raw_gather.rs"]
mod tests;
