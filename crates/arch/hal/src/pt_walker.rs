// Arch-generic 4-level 4 KiB page-table walker per `20§5` / `21§5`.
//
// This crate-root module is the manifest for the walker. Public ABI stays
// re-exported here; behavior lives in submodules grouped by operation.

mod free;
mod map;
mod migration;
mod split;
mod translate;
mod types;
mod uffd;

pub use free::{clear_swap_4k_at_root, free_user_tree, free_user_tree_leafmap, replace_present_4k_with_swap_at_root, replace_present_4k_with_swap_if_pa_at_root, replace_present_4k_flags_if_pa_at_root, replace_swap_4k_with_present_at_root, unmap_4k, unmap_4k_at_root, unmap_at_va, walk_user_swap_entries_at_root};
pub use map::{install_swap_4k_at_root, map_4k, map_at_level, map_at_level_with_root, map_device_4k};
pub use migration::{clear_migration_4k_at_root, replace_migration_4k_with_present_at_root, replace_migration_4k_with_swap_at_root, replace_present_4k_with_migration_if_pa_at_root};
pub use split::{block_output_pa, child_output_pa, leaf_present_at_root, level_span_bytes, set_leaf_present_at_root, split_kernel_leaf_at_root, split_step, SplitStep};
pub use translate::{migration_entry_4k_at_root, protect_4k_at_root, swap_entry_4k_at_root, translate_4k, translate_4k_at_root, translate_at_va};
pub use types::*;
pub use uffd::{is_poisoned_4k_at_root, is_uffd_wp_4k_at_root, read_leaf_4k_at_root, swap_leaf_if_4k_at_root, uffd_wp_range_at_root, write_leaf_4k_at_root};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod explicit_root_tests;
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate std;
