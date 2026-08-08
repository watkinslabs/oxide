// BTF object module manifest.
//
//   attr.rs    command attribute validation and decoding
//   command.rs load, ID enumeration, and descriptor publication
//   format.rs  wire-format constants and records
//   info.rs    descriptor information copyout
//   kernel.rs  the kernel's own type information and attach-target resolution
//   object.rs  canonical ID and lifetime registry
//   parse.rs   complete raw object validation and type index

mod attr;
mod command;
mod format;
mod info;
mod kernel;
mod object;
mod parse;
mod validate;

pub(super) use command::{get_fd_by_id, get_next_id, load};
pub(super) use info::get_info_by_fd;
pub(crate) use kernel::{iter_target_by_btf_id, lsm_hook_by_btf_id, published_len, published_read};

/// Highest type id any object may declare. An attach target above it names
/// no type in any object and is refused before any object is consulted.
pub(crate) const MAX_TYPE_ID: u32 = format::MAX_TYPE_ID as u32;

/// Whether an inode carries the canonical BTF object identity.
/// # C: O(1)
pub(super) fn is_object_inode(inode: &vfs::InodeRef) -> bool {
    inode.private::<object::BtfObject>().is_some()
}
