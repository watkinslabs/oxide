//! Inodes unlinked while still open.
//!
//! Module manifest:
//! - `block`: the orphan block's layout, and the pack arithmetic it forces.
//! - `list`:  the list a volume carries, and reclaim at close and at mount.

pub mod block;
pub mod list;

pub use block::{
    blocks_for, blocks_in_pack, decode, encode, encode_all, flag_word, max_orphans, pack_start_sum,
    pack_total, OrphanBlock, ORPHANS_PER_BLOCK,
};

#[cfg(test)]
#[path = "../tests/orphan.rs"]
mod tests;
