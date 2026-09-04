// Test-only policy-image builders exposed by the `test-policy` feature.

extern crate alloc;

/// A policy image that declares `process:setsched` and optionally allows it. # C: O(1)
pub fn scheduler(allow_setsched: bool) -> alloc::vec::Vec<u8> {
    crate::test_policy_fixture::scheduler(allow_setsched)
}
