//! malloc — segregated free-list allocator (docs/59§3, §6 G5). `heap` is
//! the always-built, oracle-tested algorithm; `api` is the freestanding
//! C ABI + Rust #[global_allocator].
pub mod heap;
#[cfg(feature = "freestanding")]
pub mod api;
// mallinfo/mallopt/malloc_stats/malloc_trim + mcheck/mtrace/cfree (introspection).
pub mod introspect;
