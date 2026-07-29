// Production wrapper: unit tests belong to this canonical module only.
// Integration harnesses that need the implementation directly include
// `time_common/core.rs`, so their crate-level `cfg(test)` cannot replay this
// unit-test manifest.

include!("time_common/core.rs");

#[cfg(test)]
#[path = "time_common/tests.rs"]
mod tests;
