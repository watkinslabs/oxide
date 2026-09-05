//! Host-testable admission rules for an x86-64 NT unwind transfer.

/// Validate the user mappings consumed by an unwind transfer before its live
/// return frame is changed. The callbacks are owned by the address-space
/// implementation; this policy owns only the ordering and required mappings.
/// # C: O(1) plus callback cost
pub fn valid_x64_unwind_transfer<F, G>(
    target_ip: u64,
    stack_word: u64,
    is_executable: F,
    is_writable: G,
) -> bool
where
    F: Fn(u64) -> bool,
    G: Fn(u64) -> bool,
{
    target_ip != 0 && stack_word != 0
        && is_executable(target_ip)
        && is_writable(stack_word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwind_requires_executable_continuation_and_writable_stack_word() {
        assert!(valid_x64_unwind_transfer(0x401000, 0x7fff_0000, |pc| pc == 0x401000,
            |sp| sp == 0x7fff_0000));
    }

    #[test]
    fn unwind_rejects_data_continuation_or_read_only_stack_word() {
        assert!(!valid_x64_unwind_transfer(0x601000, 0x7fff_0000, |_| false, |_| true));
        assert!(!valid_x64_unwind_transfer(0x401000, 0x7fff_0000, |_| true, |_| false));
        assert!(!valid_x64_unwind_transfer(0, 0x7fff_0000, |_| true, |_| true));
        assert!(!valid_x64_unwind_transfer(0x401000, 0, |_| true, |_| true));
    }
}
