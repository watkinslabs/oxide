// Resolving and reading the helper program.
//
// A helper runs with the initial namespace's root and a full credential set, so
// the walk starts at that namespace's root rather than at whoever happened to
// ask for the helper. The program must be a regular file the credential set may
// execute, on a mount that permits execution — the same gate an `execve` goes
// through, because a helper is an exec.

use alloc::vec::Vec;

use syscall::errno::Errno;

/// Read the helper program. Errors come back already negated, in the shape a
/// waiting caller reports:
///   * `-ENOENT` — no such program. The common case: no helper is installed.
///   * `-ENOTDIR` / `-ELOOP` / `-ENAMETOOLONG` — the walk failed
///   * `-EACCES` — not executable, not a regular file, or a `noexec` mount
///   * `-EIO` — the program could not be read off its filesystem
/// # C: O(components × dir-lookup) + O(size/PAGE)
pub fn read_program(path: &[u8]) -> Result<Vec<u8>, i32> {
    let vp = resolve(path)?;
    exec_permitted(&vp)?;
    read_all(&vp.inode).ok_or(-(Errno::Eio.as_i32()))
}

fn resolve(path: &[u8]) -> Result<vfs::VfsPath, i32> {
    if path.is_empty() { return Err(-(Errno::Enoent.as_i32())); }
    let ns = vfs::mount::current_ns();
    let root = vfs::mount::root_path_for_ns(ns).ok_or(-(Errno::Enoent.as_i32()))?;
    let text = vfs::path_from_bytes(path);
    let root_mnt = root.mnt_id;
    vfs::path_lookup_at_root_cred(
        root.dentry.clone(), root_mnt, root.dentry, root_mnt,
        &text, vfs::LookupFlags::default(), vfs::Cred::root())
        .map_err(errno_of)
}

fn exec_permitted(vp: &vfs::VfsPath) -> Result<(), i32> {
    if vp.inode.file_type() != vfs::FileType::Regular {
        // A directory is EACCES to exec, matching the file-type ladder an
        // `execve` applies before it looks at permissions.
        return Err(-(Errno::Eacces.as_i32()));
    }
    if let Some(m) = vfs::mount::mount_by_id(vp.mnt_id) {
        if m.is_noexec() || m.sb().is_noexec() || m.sb().is_sb_i_noexec() {
            return Err(-(Errno::Eacces.as_i32()));
        }
    }
    vfs::inode_permission(&vp.inode, vfs::MAY_EXEC, &vfs::Cred::root()).map_err(errno_of)
}

fn read_all(inode: &vfs::InodeRef) -> Option<Vec<u8>> {
    let total = inode.size() as usize;
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(total).ok()?;
    out.resize(total, 0u8);
    let mut off = 0usize;
    while off < total {
        match inode.read(off as u64, &mut out[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(_) => return None,
        }
    }
    if off != total { return None; }
    Some(out)
}

fn errno_of(e: vfs::VfsError) -> i32 {
    let n: i32 = match e {
        vfs::VfsError::Enoent      => Errno::Enoent.as_i32(),
        vfs::VfsError::Enotdir     => Errno::Enotdir.as_i32(),
        vfs::VfsError::Eacces      => Errno::Eacces.as_i32(),
        vfs::VfsError::Eperm       => Errno::Eperm.as_i32(),
        vfs::VfsError::Eloop       => Errno::Eloop.as_i32(),
        vfs::VfsError::Enametoolong=> Errno::Enametoolong.as_i32(),
        vfs::VfsError::Eisdir      => Errno::Eisdir.as_i32(),
        vfs::VfsError::Enomem      => Errno::Enomem.as_i32(),
        _                          => Errno::Eio.as_i32(),
    };
    -n
}
