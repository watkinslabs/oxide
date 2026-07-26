// Re-includes the REAL production futex source (B1419 hosted conformance
// harness — see `../futex_core_hosted.rs`). A real on-disk `futex/mod.rs`
// (rather than an inline `mod futex { .. }`) so the sibling `#[path]`
// includes below resolve against a directory that genuinely exists.
#[path = "../../src/live/futex/core.rs"] pub mod core;
#[path = "../../src/live/futex/wait.rs"] pub mod wait;
#[path = "../../src/live/futex/ops.rs"] pub mod ops;
