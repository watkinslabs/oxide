// Module manifest:
// - `ids`: ext4<->VFS inode id tagging helpers.
// - `data`: per-inode private state shared across inode kinds.
// - `regular`: regular-file inode/file/mapping ops + builder + seek tests.
// - `special`: directory/symlink/device inode/file ops + builder.
// - `meta`: shared `ext4_setattr` — in-core apply + on-disk metadata writeback.

mod ids;
mod data;
mod meta;
mod regular;
mod special;

pub use ids::{EXT4_INO_MARK, EXT4_INO_MASK, ext4_unwrap_ino, ext4_wrap_ino, is_ext4_ino};

#[allow(unused_imports)]
pub(crate) use data::ext4_state_of;
pub(crate) use data::Ext4FileData;
pub(crate) use regular::build_file_inode;
pub(crate) use special::build_stat_inode;
