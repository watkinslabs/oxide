// Module manifest:
// - `core`: immutable DMAR/IVRS inventory and boot publication.
// - `tests`: hosted firmware-table fixtures and parser contracts.

mod core;
pub use core::*;

#[cfg(test)] mod tests;
