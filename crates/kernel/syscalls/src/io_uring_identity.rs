//! "Is this description an io_uring ring?", and the errno each caller reports
//! when it is not (or when it must not be).
//!
//! Linux answers the question with `io_is_uring_fops` — `file->f_op ==
//! &io_uring_fops` — and exactly one constructor installs that vtable. Three
//! callers here tested the inode NUMBER's high half instead, one of them
//! (`SCM_RIGHTS` admission, in another crate entirely) from its own duplicate
//! copy of the tag. A number is reserved per owner; it is never proof of who
//! minted an inode, so a foreign inode reusing that half was admitted as a ring
//! and `io_uring_enter` then read its unrelated `i_private` as an
//! `IoUringInode`.
//!
//! Ungated on purpose: `io_uring.rs` carries `#![cfg(target_os =
//! "oxide-kernel")]`, so a `#[cfg(test)]` block anywhere beneath it compiles
//! out entirely and reports nothing.

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::File;

/// Linux `io_is_uring_fops`. # C: O(1)
pub fn is_io_uring_file(file: &Arc<File>) -> bool { file.inode().i_fop().is_io_uring() }

/// `io_uring_enter`/`io_uring_register` resolving their first argument —
/// Linux `io_uring_ctx_get_file()` reports `EOPNOTSUPP` for a live fd that is
/// not a ring, not `EINVAL` and not `EBADF`. # C: O(1)
pub fn admit_ring_fd(file: &Arc<File>) -> Result<(), Errno> {
    if is_io_uring_file(file) { Ok(()) } else { Err(Errno::Eopnotsupp) }
}

/// `IORING_REGISTER_FILES` resolving one slot — Linux refuses to register a
/// ring as a fixed file (`io_is_uring_fops` → `EBADF`), which is what stops a
/// ring from pinning itself. # C: O(1)
pub fn admit_fixed_file(file: &Arc<File>) -> Result<(), Errno> {
    if is_io_uring_file(file) { Err(Errno::Ebadf) } else { Ok(()) }
}

#[cfg(test)]
#[path = "io_uring_identity/tests.rs"]
mod tests;
