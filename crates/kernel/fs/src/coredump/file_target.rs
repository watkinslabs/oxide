// Writing a dump to the file the pattern named.
//
// Walk the namespace the crashing process sees, create the target exclusively,
// check what was created against the admission ladder, then stream the body in.
// No step may be skipped and none may be reordered: the exclusive create is
// what stops a symlink planted at the path from redirecting the dump, and the
// check-after-create is what stops a backend that could not honour the mode
// from publishing it.

#![cfg(target_os = "oxide-kernel")]

use vfs::{CreateCtx, Cred, InodeRef, LookupFlags};

use super::file::{admit_created, may_unlink_existing, split_parent, CreatedTarget, CORE_FILE_MODE};
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
    let Some((dir, name)) = split_parent(path) else { return false };
    let Some(parent) = lookup_dir(dir) else { return false };
    // The dump is created as the dying process's owner, not as root: the file
    // must end up belonging to whoever crashed, and the admission ladder below
    // refuses it if the backend recorded anyone else.
    let cred = Cred { uid: fsuid, gid: fsgid, ..Cred::root() };
    let ctx = CreateCtx { idmap: &vfs::idmap::IDENTITY, cred: &cred, umask: 0 };

    // Failure is ignored on purpose: whatever the reason the name could not be
    // removed, the exclusive create below is what decides the outcome.
    if may_unlink_existing(force_suid_safe) { let _ = parent.unlink_child(name); }

    let inode = match parent.create_child(name, CORE_FILE_MODE, &ctx) {
        Ok(i) => i,
        // A racing dump of another thread of the same process won the create.
        // One of the two dumps lands, which is all that was ever promised.
        Err(_) => return false,
    };
    let target = CreatedTarget {
        file_type: inode.file_type(),
        nlink: inode.nlink(),
        uid: inode.uid().unwrap_or(u32::MAX),
        perm: inode.perm().unwrap_or(0),
    };
    if admit_created(&target, fsuid).is_err() {
        // The target is not fit to hold the dump. Remove it rather than leave a
        // zero-length file that reads as a dump that was taken.
        let _ = parent.unlink_child(name);
        return false;
    }
    let mut off = 0u64;
    let d = deliver(body, DUMP_CHUNK, &mut |c| match inode.write(off, c) {
        Ok(0) | Err(_) => Chunk::Refused,
        Ok(n) => { off += n as u64; Chunk::Took(n) }
    });
    d.written > 0
}

/// Resolve a directory in the namespace the crashing process sees, refusing to
/// follow a symlink as the final component.
fn lookup_dir(dir: &str) -> Option<InodeRef> {
    let ns = vfs::mount::current_ns();
    let root = vfs::mount::root_path_for_ns(ns)?;
    let root_mnt = root.mnt_id;
    let flags = LookupFlags { no_follow_final: true, ..LookupFlags::default() };
    let vp = vfs::path_lookup_at_root_cred(
        root.dentry.clone(), root_mnt, root.dentry, root_mnt, dir, flags, Cred::root()).ok()?;
    if vp.inode.file_type() != vfs::FileType::Directory { return None; }
    Some(vp.inode)
}
