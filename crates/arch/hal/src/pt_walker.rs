// Arch-generic 4-level 4 KiB page-table walker per `20§5` / `21§5`.
//
// This crate-root module is the manifest for the walker. Public ABI stays
// re-exported here; behavior lives in submodules grouped by operation.

mod free;
mod map;
mod migration;
mod translate;
mod types;

pub use free::{clear_swap_4k_at_root, free_user_tree, free_user_tree_leafmap, replace_present_4k_with_swap_at_root, replace_present_4k_with_swap_if_pa_at_root, replace_present_4k_flags_if_pa_at_root, replace_swap_4k_with_present_at_root, unmap_4k, unmap_4k_at_root, unmap_at_va, walk_user_swap_entries_at_root};
pub use map::{install_swap_4k_at_root, map_4k, map_at_level, map_at_level_with_root, map_device_4k};
pub use migration::{clear_migration_4k_at_root, replace_migration_4k_with_present_at_root, replace_migration_4k_with_swap_at_root, replace_present_4k_with_migration_if_pa_at_root};
pub use translate::{migration_entry_4k_at_root, protect_4k_at_root, swap_entry_4k_at_root, translate_4k, translate_4k_at_root, translate_at_va};
pub use types::*;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod explicit_root_tests;
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate std;
