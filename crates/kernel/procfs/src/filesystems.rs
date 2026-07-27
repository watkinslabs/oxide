// /proc/filesystems — every registered filesystem type, rendered from the LIVE
// `vfs::fs` type registry (Linux `fs/filesystems.c` `filesystems_proc_show`).
// The registry is the same list `sysfs(2)` indexes, so the file and the syscall
// cannot disagree; a hardcoded body could and did.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

fn body() -> Vec<u8> { vfs::fs::filesystems_proc_body() }

/// `/proc/filesystems` inode. # C: O(1)
pub fn make_proc_filesystems() -> InodeRef {
    crate::dyn_file::make_gen_file(crate::ids::FILESYSTEMS as Ino, body)
}
