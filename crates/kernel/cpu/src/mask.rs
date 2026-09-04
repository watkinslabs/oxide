// Module manifest:
// - value: fixed-capacity CPU set and atomic publication storage.
// - latch: coherent two-copy seqcount-latch protocol.
// - tests: value, publication, and concurrency coverage.

mod latch;
mod value;

pub use value::{AtomicCpuMask, CpuMask, CPU_MASK_WORD_BITS, CPU_MASK_WORDS};

#[cfg(test)]
#[path = "mask/tests.rs"]
mod tests;
