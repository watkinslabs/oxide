use alloc::string::String;
use alloc::sync::{Arc, Weak};

use vfs::{CreateCtx, FileType, InodeRef, VfsError};

use super::{TmpfsFs, TmpfsSb};
use super::dir::make_tmpfs_dir_inode;
use super::file::make_tmpfs_file_inode;
use super::limits::{PG, ROOT_INO};
use super::symlink::make_tmpfs_symlink_inode;
use super::uapi::TMPFS_MAGIC;


#[cfg(test)]
mod iget;
#[cfg(test)]
mod rename;
#[cfg(test)]
mod shmem_page;

#[cfg(test)]
mod statfs;
#[cfg(test)]
mod rename_overwrite;
#[cfg(test)]
mod symlink;
#[cfg(test)]
mod nlink_mode;
#[cfg(test)]
mod xattr;

mod mount_opts;
mod quota;

