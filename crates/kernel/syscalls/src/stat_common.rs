// Production wrapper: unit tests belong to this canonical module only.
// Integration harnesses that need the implementation directly include
// `stat_common/core.rs`, so their crate-level `cfg(test)` cannot replay this
// unit-test manifest.

include!("stat_common/core.rs");

#[cfg(test)]
#[path = "stat_common/tests.rs"]
mod tests;
