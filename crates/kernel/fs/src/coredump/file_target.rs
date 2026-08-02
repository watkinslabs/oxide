// Writing a dump to the file the pattern named.
//
// The dump opens its target the way anything else opens a file: through the
// kernel's own open path, in the namespace the crashing process sees, with the
// crashing process's ownership. It then checks what it actually opened against
// the admission ladder before a byte is written, and writes through the open
// description.
//
// It does NOT create through the directory inode. Doing that leaves the name
// unpublished in the dentry cache, so the dump is written and then unreachable:
// the file sits in the directory, a directory listing shows it, and every
// lookup of its path reports ENOENT.

#![cfg(target_os = "oxide-kernel")]

use vfs::Cred;

use super::file::{admit_opened, core_open_flags, split_parent, OpenedTarget, CORE_FILE_MODE};
use super::stream::{deliver, Chunk};

/// Bytes handed to the backend per write. A dump is emitted a page at a time,
/// which is also the granularity the size limit binds at.
const DUMP_CHUNK: usize = hal::PAGE_SIZE_BYTES as usize;

/// Write `body` to `path`, as the dying process's owner.
///
/// Returns false when no dump reached the filesystem. A partial write is NOT a
/// failure — a truncated core is still readable — so the count, not the flag,
/// says how much landed.
/// # C: O(components × dir-lookup) + O(len)
pub fn write_to_file(path: &str, body: &[u8], fsuid: u32, fsgid: u32, force_suid_safe: bool) -> bool {
    // Refused before the namespace is walked: a path naming no final component
    // names a directory, and a dump is not a directory.
    if split_parent(path).is_none() { return false }
    let ns = vfs::mount::current_ns();
    let Some(root) = vfs::mount::root_path_for_ns(ns) else { return false };
    // The dump belongs to whoever crashed, not to the kernel: it must end up
    // owned by them, and the ladder below refuses it if it did not.
    let cred = Cred { uid: fsuid, gid: fsgid, ..Cred::root() };
    let Ok(file) = vfs::file::kernel_open_at_root(
        &root.dentry, root.mnt_id, path, core_open_flags(force_suid_safe),
        CORE_FILE_MODE, cred) else { return false };

    let inode = file.inode();
    let target = OpenedTarget {
        file_type: inode.file_type(),
        nlink: inode.nlink(),
        uid: inode.uid().unwrap_or(u32::MAX),
        perm: inode.perm().unwrap_or(0),
        hashed: file.dentry().is_hashed(),
        writable: file.f_mode().contains(vfs::Fmode::WRITE),
    };
    if admit_opened(&target, fsuid).is_err() { return false }
    // An ordinary dump reuses whatever name was already there, so yesterday's
    // larger core must not show through the tail of today's smaller one.
    if inode.truncate(0).is_err() { return false }

    let d = deliver(body, DUMP_CHUNK, &mut |c| match file.write(c) {
        Ok(0) | Err(_) => Chunk::Refused,
        Ok(n) => Chunk::Took(n),
    });
    d.written > 0
}
