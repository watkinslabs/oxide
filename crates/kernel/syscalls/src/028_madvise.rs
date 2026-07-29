// Production wrapper: unit tests belong to this canonical module only.
// Integration harnesses that need the implementation directly include
// `028_madvise/core.rs`, so their crate-level `cfg(test)` cannot replay this
// unit-test manifest.
#![cfg(any(target_os = "oxide-kernel", test))]

include!("028_madvise/core.rs");

#[cfg(test)]
#[path = "028_madvise/tests.rs"]
mod tests;
