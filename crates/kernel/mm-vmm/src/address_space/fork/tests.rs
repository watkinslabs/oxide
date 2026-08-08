// Fork's parent-side copy-on-write decision.

#[cfg(test)]
mod tests {
    use crate::address_space::fork::shared::needs_cow_wrprotect;

    /// The parent's copy-on-write strip must skip a leaf that is already
    /// read-only. Rewriting one from the VMA protection destroys the per-page
    /// userfaultfd write-protect marker, which is the whole barrier: the next
    /// write would copy the page instead of being reported to the monitor.
    #[test]
    fn fork_does_not_rewrite_an_already_read_only_parent_leaf() {
        assert!(needs_cow_wrprotect(true, false, true));
        assert!(!needs_cow_wrprotect(true, false, false),
                "an already read-only leaf must be left exactly as it is");
        assert!(!needs_cow_wrprotect(false, false, true));
        assert!(!needs_cow_wrprotect(true, true, true), "shared pages are not split");
    }
}
