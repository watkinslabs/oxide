// aarch64 suspend-to-disk architecture manifest (`32b§11`).
//
// Module manifest:
// - `plan`: persistent header, safe-memory operands and admission.
// - `tables`: safe TTBR0 identity and temporary TTBR1 construction.
// - `restore`: copied stackless collision restore and context handoff.

mod plan;
pub use plan::*;
mod tables;
pub use tables::build_temporary_tables;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod restore;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub use restore::{capture_image_continuation, current_header, header_from_captured_state, restore,
    restore_path_available};

#[cfg(test)]
#[path = "hibernate/tests.rs"]
mod tests;
