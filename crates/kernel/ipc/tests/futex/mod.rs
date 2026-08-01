// Re-includes the REAL production futex source (B1419 hosted conformance
// harness — see `../futex_core_hosted.rs`). A real on-disk `futex/mod.rs`
// (rather than an inline `mod futex { .. }`) so the sibling `#[path]`
// includes below resolve against a directory that genuinely exists.
// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
#[path = "../../src/live/futex/core.rs"] pub mod core;
#[path = "../../src/live/futex/wait.rs"] pub mod wait;
#[path = "../../src/live/futex/ops.rs"] pub mod ops;
// `wait.rs` routes the PI commands into `pi`, so the real PI tree is compiled
// here too. Its own outcome tests live in `futex_pi_hosted.rs`; this harness
// only needs it present and real, never stubbed.
pub mod pi;
