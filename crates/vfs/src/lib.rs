// Virtual File System — superblock / dentry / inode.
//
// Per docs/16 (FROZEN). Foundation lands here:
//   - shared types + errno (`types.rs`)
//   - `Inode` trait (`inode.rs`, v1 subset)
//   - `Dentry` (`dentry.rs`)
//   - `File` (`file.rs`) with read/write/seek + O_APPEND + O_RDONLY/WRONLY checks
//   - `FdTable` (`fdtable.rs`) with alloc/get/close/dup/dup2/CLOEXEC
//   - lexical path splitting (`path.rs`)
//
// Caches (`16§4` open-addressed hash + RCU), Superblock impls,
// Filesystem trait, mount table (`16§6`), full `Inode` surface, and
// `path_lookup` with symlink + RESOLVE_BENEATH + mount crossing all
// land in subsequent P1-N branches.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod dentry;
pub mod dirent;
pub mod fdtable;
pub mod file;
pub mod inode;
pub mod path;
pub mod types;

pub use dentry::Dentry;
pub use dirent::{dirent64_pack, dirent64_reclen, DIRENT64_HEADER};
pub use fdtable::{FdTable, FD_TABLE_MAX};
pub use file::{File, SeekFrom};
pub use inode::{Inode, InodeRef};
pub use types::{FileMode, FileType, Ino, KResult, OpenFlags, PollMask, StatxMask, VfsError};

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical VFS error is `VfsError` above.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}
