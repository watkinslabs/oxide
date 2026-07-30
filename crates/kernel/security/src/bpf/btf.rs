// BTF object module manifest.
//
//   attr.rs    command attribute validation and decoding
//   command.rs load, ID enumeration, and descriptor publication
//   format.rs  wire-format constants and records
//   info.rs    descriptor information copyout
//   object.rs  canonical ID and lifetime registry
//   parse.rs   complete raw object validation and type index

mod attr;
mod command;
mod format;
mod info;
mod object;
mod parse;
mod validate;

pub(super) use command::{get_fd_by_id, get_next_id, load};
pub(super) use info::get_info_by_fd;

/// Whether an inode carries the canonical BTF object identity.
/// # C: O(1)
pub(super) fn is_object_inode(inode: &vfs::InodeRef) -> bool {
    inode.private::<object::BtfObject>().is_some()
}
