// Module manifest:
// - core: CPU-set value and atomic publication coverage.
// - loom: exhaustive latch concurrency models.

#[path = "tests/core.rs"]
mod core;
#[cfg(loom)]
#[path = "tests/loom.rs"]
mod loom;
