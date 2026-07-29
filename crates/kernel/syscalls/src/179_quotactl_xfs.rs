// Production wrapper: unit tests belong to this canonical module only.
// Integration harnesses that need the implementation directly include
// `179_quotactl_xfs/core.rs`, so their crate-level `cfg(test)` cannot replay
// this unit-test manifest.

include!("179_quotactl_xfs/core.rs");

#[cfg(test)]
#[path = "179_quotactl_xfs/tests.rs"]
mod tests;
