// x86_64 suspend-to-disk architecture path (`32b§11`).
//
// Module manifest:
// - `contract`: persistent header, collision/control layouts and admission.
// - `save`:     CPU-state and continuation capture around the image callback.
// - `tables`:   safe temporary direct and restored-text mappings.
// - `terminal`: copied stack-independent collision loop and final CR3 jump.

mod contract;
mod save;
mod tables;
mod terminal;

pub use contract::*;
pub use save::{capture_image_continuation, header_from_captured_state};
pub use tables::{build_temporary_tables, BLOCK_BYTES};
pub use terminal::{enter_terminal, install_terminal, restore_entry_pa, restore_entry_va,
    terminal_blob_len, TerminalEntry};

#[cfg(test)]
#[path = "hibernate/tests.rs"]
mod tests;
