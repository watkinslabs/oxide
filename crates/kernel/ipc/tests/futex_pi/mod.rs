// Re-includes the REAL production PI-futex + robust-walk source. A real
// on-disk `futex_pi/mod.rs` (rather than an inline `mod`) so the `#[path]`
// includes resolve against a directory that genuinely exists — same technique
// as `tests/futex/mod.rs`.
// This integration test compiles production modules directly via `#[path]` to
// assert their behaviour, and exercises only the part of each module the
// outcome under test needs. dead_code here measures the test's reach, not the
// kernel's -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
#[path = "../../src/live/futex/core.rs"] pub mod core;
#[path = "../../src/live/futex/wait.rs"] pub mod wait;
#[path = "../../src/live/futex/ops.rs"] pub mod ops;
#[path = "../../src/live/futex/robust.rs"] pub mod robust;

pub mod pi;
