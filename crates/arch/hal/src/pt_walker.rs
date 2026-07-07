// Arch-generic 4-level 4 KiB page-table walker per `20§5` / `21§5`.
//
// This crate-root module is the manifest for the walker. Public ABI stays
// re-exported here; behavior lives in submodules grouped by operation.

mod free;
mod map;
mod translate;
mod types;

pub use free::{free_user_tree, free_user_tree_leafmap, unmap_4k, unmap_4k_at_root, unmap_at_va};
pub use map::{map_4k, map_at_level, map_at_level_with_root, map_device_4k};
pub use translate::{protect_4k_at_root, translate_4k, translate_4k_at_root, translate_at_va};
pub use types::*;

#[cfg(test)]
mod tests;
#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate std;
